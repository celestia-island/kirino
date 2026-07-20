use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::{
    braced, parenthesized,
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    Ident, Token, Visibility,
};

struct HierarchicalPermission {
    attrs: Vec<syn::Attribute>,
    vis: Visibility,
    enum_name: Ident,
    domains: Vec<DomainEntry>,
}

struct DomainEntry {
    name: Ident,
    actions: Vec<Ident>,
}

impl Parse for HierarchicalPermission {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let attrs = syn::Attribute::parse_outer(input)?;
        let vis: Visibility = input.parse()?;

        input.parse::<Token![enum]>()?;
        let enum_name: Ident = input.parse()?;

        let content;
        braced!(content in input);

        let mut domains = Vec::new();
        while !content.is_empty() {
            let domain_name: Ident = content.parse()?;

            let parens;
            parenthesized!(parens in content);

            let actions: Punctuated<Ident, Token![,]> =
                parens.parse_terminated(Ident::parse, Token![,])?;

            domains.push(DomainEntry {
                name: domain_name,
                actions: actions.into_iter().collect(),
            });

            if content.peek(Token![,]) {
                content.parse::<Token![,]>()?;
            } else {
                break;
            }
        }

        Ok(HierarchicalPermission {
            attrs,
            vis,
            enum_name,
            domains,
        })
    }
}

fn domain_snake(name: &Ident) -> String {
    let s = name.to_string();
    let mut result = String::with_capacity(s.len() + 4);
    for (i, ch) in s.char_indices() {
        if ch.is_uppercase() {
            if i > 0 {
                result.push('_');
            }
            result.push(ch.to_ascii_lowercase());
        } else {
            result.push(ch);
        }
    }
    result
}

fn action_snake(name: &Ident) -> String {
    name.to_string().to_lowercase()
}

struct LeafData {
    domain_ident: Ident,
    action_ident: Ident,
    domain_snake: String,
    action_snake: String,
    leaf_name: String,
}

#[proc_macro]
pub fn hierarchical_permission(input: TokenStream) -> TokenStream {
    let HierarchicalPermission {
        attrs,
        vis,
        enum_name,
        domains,
    } = parse_macro_input!(input as HierarchicalPermission);

    let inner_mod_name = format_ident!("__{}_inner", enum_name.to_string().to_lowercase());
    let inner_attrs = filter_derive_attrs(&attrs);

    let mut inner_enums = Vec::new();
    let mut outer_variants: Vec<TokenStream2> = Vec::new();
    let mut domain_arms: Vec<TokenStream2> = Vec::new();
    let mut all_domain_strs: Vec<String> = Vec::new();
    let mut all_leaves: Vec<TokenStream2> = Vec::new();

    let mut leaves: Vec<LeafData> = Vec::new();

    for domain in &domains {
        let domain_ident = &domain.name;
        let domain_snake_str = domain_snake(domain_ident);

        let action_variants: Vec<&Ident> = domain.actions.iter().collect();
        let inner_enum_def = quote! {
            #(#inner_attrs)*
            #[serde(rename_all = "snake_case")]
            pub enum #domain_ident {
                #(#action_variants),*
            }
        };
        inner_enums.push(inner_enum_def);

        outer_variants.push(quote! { #domain_ident(#inner_mod_name::#domain_ident) });

        let domain_arm = quote! {
            Self::#domain_ident(_) => #domain_snake_str,
        };
        domain_arms.push(domain_arm);

        all_domain_strs.push(domain_snake_str.clone());

        for action in &domain.actions {
            let action_ident = action;
            let action_snake_str = action_snake(action_ident);
            let leaf_name = format!("{}.{}", domain_snake_str, action_snake_str);

            let all_leaf = quote! {
                Self::#domain_ident(#inner_mod_name::#domain_ident::#action_ident)
            };
            all_leaves.push(all_leaf);

            leaves.push(LeafData {
                domain_ident: domain_ident.clone(),
                action_ident: action_ident.clone(),
                domain_snake: domain_snake_str.clone(),
                action_snake: action_snake_str,
                leaf_name,
            });
        }
    }

    let name_arms: Vec<TokenStream2> = leaves
        .iter()
        .map(|leaf| {
            let LeafData {
                domain_ident,
                action_ident,
                leaf_name,
                ..
            } = leaf;
            quote! {
                Self::#domain_ident(#inner_mod_name::#domain_ident::#action_ident) => #leaf_name,
            }
        })
        .collect();

    let path_segments_arms: Vec<TokenStream2> = leaves
        .iter()
        .map(|leaf| {
            let LeafData {
                domain_ident,
                action_ident,
                domain_snake,
                action_snake,
                ..
            } = leaf;
            quote! {
                Self::#domain_ident(#inner_mod_name::#domain_ident::#action_ident) => &[#domain_snake, #action_snake],
            }
        })
        .collect();

    let from_path_arms: Vec<TokenStream2> = leaves
        .iter()
        .map(|leaf| {
            let LeafData {
                domain_ident,
                action_ident,
                leaf_name,
                ..
            } = leaf;
            quote! {
                #leaf_name => Some(Self::#domain_ident(#inner_mod_name::#domain_ident::#action_ident)),
            }
        })
        .collect();

    let expand_domain_arms: Vec<TokenStream2> = domains
        .iter()
        .map(|domain| {
            let domain_ident = &domain.name;
            let domain_snake_str = domain_snake(domain_ident);
            let action_tokens: Vec<TokenStream2> = domain
                .actions
                .iter()
                .map(|action| {
                    quote! { Self::#domain_ident(#inner_mod_name::#domain_ident::#action) }
                })
                .collect();
            quote! {
                #domain_snake_str => vec![#(#action_tokens),*],
            }
        })
        .collect();

    let outer_attrs = attrs;

    let expanded = quote! {
        #[allow(non_snake_case)]
        mod #inner_mod_name {
            use serde::{Serialize, Deserialize};

            #(#inner_enums)*
        }

        #(#outer_attrs)*
        #vis enum #enum_name {
            #(#outer_variants),*
        }

        impl #enum_name {
            pub fn name(&self) -> &'static str {
                match self {
                    #(#name_arms)*
                }
            }

            pub fn domain(&self) -> &'static str {
                match self {
                    #(#domain_arms)*
                }
            }

            pub fn path_segments(&self) -> &'static [&'static str] {
                match self {
                    #(#path_segments_arms)*
                }
            }

            pub fn ancestry_names(&self) -> Vec<&'static str> {
                vec![self.domain(), self.name()]
            }

            pub fn matches_pattern(&self, pattern: &str) -> bool {
                pattern == self.domain() || pattern == self.name()
            }

            pub fn is_leaf(&self) -> bool {
                true
            }

            pub fn is_branch(&self) -> bool {
                false
            }

            pub fn all() -> Vec<Self> {
                vec![
                    #(#all_leaves),*
                ]
            }

            pub fn all_domains() -> Vec<&'static str> {
                vec![
                    #(#all_domain_strs),*
                ]
            }

            pub fn from_path(path: &str) -> Option<Self> {
                match path {
                    #(#from_path_arms)*
                    _ => None,
                }
            }

            pub fn expand_domain(domain_str: &str) -> Vec<Self> {
                match domain_str {
                    #(#expand_domain_arms)*
                    _ => Vec::new(),
                }
            }
        }
    };

    expanded.into()
}

fn filter_derive_attrs(attrs: &[syn::Attribute]) -> Vec<syn::Attribute> {
    attrs
        .iter()
        .filter(|a| a.path().is_ident("derive") || a.path().is_ident("serde"))
        .cloned()
        .collect()
}
