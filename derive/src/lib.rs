// The `aligned_borrow_derive` macro is taken from valida-xyz/valida under MIT license
//
// The MIT License (MIT)
//
// Copyright (c) 2023 The Valida Authors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

use proc_macro::TokenStream;
use quote::quote;
use syn::parse_macro_input;
use syn::parse_quote;
use syn::Data;
use syn::DeriveInput;
use syn::GenericParam;
use syn::ItemFn;
use syn::WherePredicate;

#[proc_macro_derive(AlignedBorrow)]
pub fn aligned_borrow_derive(input: TokenStream) -> TokenStream {
    let ast = parse_macro_input!(input as DeriveInput);
    let name = &ast.ident;

    // Get first generic which must be type (ex. `T`) for input <T, N: NumLimbs, const M: usize>
    let type_generic = ast
        .generics
        .params
        .iter()
        .map(|param| match param {
            GenericParam::Type(type_param) => &type_param.ident,
            _ => panic!("Expected first generic to be a type"),
        })
        .next()
        .expect("Expected at least one generic");

    // Get generics after the first (ex. `N: NumLimbs, const M: usize`)
    // We need this because when we assert the size, we want to substitute u8 for T.
    let non_first_generics = ast
        .generics
        .params
        .iter()
        .skip(1)
        .filter_map(|param| match param {
            GenericParam::Type(type_param) => Some(&type_param.ident),
            GenericParam::Const(const_param) => Some(&const_param.ident),
            _ => None,
        })
        .collect::<Vec<_>>();

    // Get impl generics (`<T, N: NumLimbs, const M: usize>`), type generics (`<T, N>`), where clause (`where T: Clone`)
    let (impl_generics, type_generics, where_clause) = ast.generics.split_for_impl();

    let methods = quote! {
        impl #impl_generics core::borrow::Borrow<#name #type_generics> for [#type_generic] #where_clause {
            fn borrow(&self) -> &#name #type_generics {
                debug_assert_eq!(self.len(), std::mem::size_of::<#name<u8 #(, #non_first_generics)*>>());
                let (prefix, shorts, _suffix) = unsafe { self.align_to::<#name #type_generics>() };
                debug_assert!(prefix.is_empty(), "Alignment should match");
                debug_assert_eq!(shorts.len(), 1);
                &shorts[0]
            }
        }

        impl #impl_generics core::borrow::BorrowMut<#name #type_generics> for [#type_generic] #where_clause {
            fn borrow_mut(&mut self) -> &mut #name #type_generics {
                debug_assert_eq!(self.len(), std::mem::size_of::<#name<u8 #(, #non_first_generics)*>>());
                let (prefix, shorts, _suffix) = unsafe { self.align_to_mut::<#name #type_generics>() };
                debug_assert!(prefix.is_empty(), "Alignment should match");
                debug_assert_eq!(shorts.len(), 1);
                &mut shorts[0]
            }
        }
    };

    TokenStream::from(methods)
}

/// Derives WithEvents for an enum which every variant has one field,
/// each of which implements WithEvents.
///
/// The derived implementation is a tuple of the Events of each variant,
/// in the variant declaration order. That is, because the chip could be *any* v>
/// it requires being able to provide for *all* event types consumable by each c>
#[proc_macro_derive(WithEvents, attributes(sphinx_core_path))]
pub fn with_events_air_derive(input: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(input).unwrap();

    let name = &ast.ident;
    let generics = &ast.generics;
    let type_params = generics.type_params();
    let const_params = generics.const_params();

    let sphinx_core_path = find_sphinx_core_path(&ast.attrs);
    let (_, ty_generics, where_clause) = generics.split_for_impl();

    match &ast.data {
        Data::Struct(_) | Data::Union(_) => unimplemented!("Only Enums are supported yet"),
        Data::Enum(e) => {
            let fields = e
                .variants
                .iter()
                .map(|variant| {
                    let mut fields = variant.fields.iter();
                    let field = fields.next().unwrap();
                    assert!(
                        fields.next().is_none(),
                        "Only one field per variant is supported"
                    );
                    field
                })
                .collect::<Vec<_>>();

            let field_ty_events = fields.iter().map(|field| {
                let field_ty = &field.ty;
                quote! {
                    <#field_ty as #sphinx_core_path::air::WithEvents<'a>>::Events
                }
            });
            quote!{
                impl <'a, #(#type_params),*, #(#const_params),*> #sphinx_core_path::air::WithEvents<'a> for #name #ty_generics #where_clause {
                    type Events = (#(#field_ty_events,)*);
                }
            }.into()
        }
    }
}

fn get_type_from_attrs(attrs: &[syn::Attribute], attr_name: &str) -> syn::Result<syn::LitStr> {
    attrs
        .iter()
        .find(|attr| attr.path.is_ident(attr_name))
        .map_or_else(
            || {
                Err(syn::Error::new(
                    proc_macro2::Span::call_site(),
                    format!("Could not find attribute {}", attr_name),
                ))
            },
            |attr| match attr.parse_meta()? {
                syn::Meta::NameValue(meta) => {
                    if let syn::Lit::Str(lit) = &meta.lit {
                        Ok(lit.clone())
                    } else {
                        Err(syn::Error::new_spanned(
                            meta,
                            &format!("Could not parse {} attribute", attr_name)[..],
                        ))
                    }
                }
                bad => Err(syn::Error::new_spanned(
                    bad,
                    &format!("Could not parse {} attribute", attr_name)[..],
                )),
            },
        )
}

/// Derives EventLens for an enum which every variant has one field,
/// each of which the input record implements EventLens for.
///
/// The derived implementation is a delegation to the events of each variant,
/// in the variant declaration order.
///
/// This makes the strong assumption that the `WithEvents` trait is implemented on `Self`
/// as a tuple of the `WithEvents` of each variant. This is what the `WithEvents` derive macro does.
#[proc_macro_derive(EventLens, attributes(sphinx_core_path, record_type))]
pub fn event_lens_air_derive(input: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(input).unwrap();

    let name = &ast.ident;
    let generics = &ast.generics;
    let record_type = get_type_from_attrs(&ast.attrs, "record_type").unwrap();
    let rec_ty: syn::Type = record_type.parse().unwrap();

    let sphinx_core_path = find_sphinx_core_path(&ast.attrs);
    let (impl_generics, ty_generics, _) = generics.split_for_impl();

    match &ast.data {
        Data::Struct(_) | Data::Union(_) => unimplemented!("Only Enums are supported yet"),
        Data::Enum(e) => {
            let fields = e
                .variants
                .iter()
                .map(|variant| {
                    let mut fields = variant.fields.iter();
                    let field = fields.next().unwrap();
                    assert!(
                        fields.next().is_none(),
                        "Only one field per variant is supported"
                    );
                    field
                })
                .collect::<Vec<_>>();

            let field_events = fields.iter().map(|field| {
                let field_ty = &field.ty;
                quote! {
                    #sphinx_core_path::air::EventLens::<#field_ty>::events(self)
                }
            });
            let res = quote! {
                impl #impl_generics #sphinx_core_path::air::EventLens<#name #ty_generics> for #rec_ty {
                    fn events(&self) -> <#name #ty_generics as #sphinx_core_path::air::WithEvents>::Events {
                        (#(#field_events,)*)
                    }
                }
            };
            res.into()
        }
    }
}

#[proc_macro_derive(
    MachineAir,
    attributes(
        sphinx_core_path,
        execution_record_path,
        program_path,
        builder_path,
        eval_trait_bound
    )
)]
pub fn machine_air_derive(input: TokenStream) -> TokenStream {
    let ast: DeriveInput = syn::parse(input).unwrap();

    let name = &ast.ident;
    let generics = &ast.generics;
    let type_params = generics.type_params();
    let ty_params = quote! { #(#type_params),* };
    let const_params = generics.const_params();
    let co_params = quote! { #(#const_params),* };

    let sphinx_core_path = find_sphinx_core_path(&ast.attrs);
    let execution_record_path = find_execution_record_path(&ast.attrs);
    let program_path = find_program_path(&ast.attrs);
    let builder_path = find_builder_path(&ast.attrs);
    let eval_trait_bound = find_eval_trait_bound(&ast.attrs);
    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();
    let turbo_ty = ty_generics.as_turbofish();

    match &ast.data {
        Data::Struct(_) => unimplemented!("Structs are not supported yet"),
        Data::Enum(e) => {
            let variants = e
                .variants
                .iter()
                .map(|variant| {
                    let variant_name = &variant.ident;

                    let mut fields = variant.fields.iter();
                    let field = fields.next().unwrap();
                    assert!(
                        fields.next().is_none(),
                        "Only one field per variant is supported"
                    );
                    (variant_name, field)
                })
                .collect::<Vec<_>>();

            let width_arms = variants.iter().map(|(variant_name, field)| {
                let field_ty = &field.ty;
                quote! {
                    #name::#variant_name(x) => <#field_ty as p3_air::BaseAir<F>>::width(x)
                }
            });

            let base_air = quote! {
                impl #impl_generics p3_air::BaseAir<F> for #name #ty_generics #where_clause {
                    fn width(&self) -> usize {
                        match self {
                            #(#width_arms,)*
                        }
                    }

                    fn preprocessed_trace(&self) -> Option<p3_matrix::dense::RowMajorMatrix<F>> {
                        unreachable!("A machine air should use the preprocessed trace from the `MachineAir` trait")
                    }
                }
            };

            let name_arms = variants.iter().map(|(variant_name, field)| {
                let field_ty = &field.ty;
                quote! {
                    #name::#variant_name(x) => <#field_ty as #sphinx_core_path::air::MachineAir<F>>::name(x)
                }
            });

            let preprocessed_width_arms = variants.iter().map(|(variant_name, field)| {
                let field_ty = &field.ty;
                quote! {
                    #name::#variant_name(x) => <#field_ty as #sphinx_core_path::air::MachineAir<F>>::preprocessed_width(x)
                }
            });

            let generate_preprocessed_trace_arms = variants.iter().map(|(variant_name, field)| {
                let field_ty = &field.ty;
                quote! {
                    #name::#variant_name(x) => <#field_ty as #sphinx_core_path::air::MachineAir<F>>::generate_preprocessed_trace(x, program)
                }
            });

            let generate_trace_arms = variants.iter().enumerate().map(|(i, (variant_name, field))| {
                let field_ty = &field.ty;

                let idx = syn::Index::from(i);
                quote! {
                    #name::#variant_name(x) => {
                        fn f <'c, #ty_params, #co_params> (evs: <#name #ty_generics as #sphinx_core_path::air::WithEvents<'c>>::Events, _v: &'c ()) -> <#field_ty as #sphinx_core_path::air::WithEvents<'c>>::Events  { evs.#idx }

                        <#field_ty as #sphinx_core_path::air::MachineAir<F>>::generate_trace(x, &#sphinx_core_path::air::Proj::new(input, f #turbo_ty), output)
                    }
                }
            });

            let generate_dependencies_arms = variants.iter().enumerate().map(|(i, (variant_name, field))| {
                let field_ty = &field.ty;
                let idx = syn::Index::from(i);

                quote! {
                    #name::#variant_name(x) => {
                        fn f <'c, #ty_params, #co_params> (evs: <#name #ty_generics as #sphinx_core_path::air::WithEvents<'c>>::Events, _v: &'c ()) -> <#field_ty as #sphinx_core_path::air::WithEvents<'c>>::Events  { evs.#idx }

                        <#field_ty as #sphinx_core_path::air::MachineAir<F>>::generate_dependencies(x, &#sphinx_core_path::air::Proj::new(input, f #turbo_ty), output)
                    }
                }
            });

            let included_arms = variants.iter().map(|(variant_name, field)| {
                let field_ty = &field.ty;
                quote! {
                    #name::#variant_name(x) => <#field_ty as #sphinx_core_path::air::MachineAir<F>>::included(x, shard)
                }
            });

            let machine_air = quote! {
                impl #impl_generics #sphinx_core_path::air::MachineAir<F> for #name #ty_generics #where_clause {
                    type Record = #execution_record_path;

                    type Program = #program_path;

                    fn name(&self) -> String {
                        match self {
                            #(#name_arms,)*
                        }
                    }

                    fn preprocessed_width(&self) -> usize {
                        match self {
                            #(#preprocessed_width_arms,)*
                        }
                    }

                    fn generate_preprocessed_trace(
                        &self,
                        program: &#program_path,
                    ) -> Option<p3_matrix::dense::RowMajorMatrix<F>> {
                        match self {
                            #(#generate_preprocessed_trace_arms,)*
                        }
                    }

                    fn generate_trace<EL: #sphinx_core_path::air::EventLens<Self>>(
                        &self,
                        input: &EL,
                        output: &mut #execution_record_path,
                    ) -> p3_matrix::dense::RowMajorMatrix<F> {
                        match self {
                            #(#generate_trace_arms,)*
                        }
                    }

                    fn generate_dependencies<EL: #sphinx_core_path::air::EventLens<Self>>(
                        &self,
                        input: &EL,
                        output: &mut #execution_record_path,
                    ) {
                        match self {
                            #(#generate_dependencies_arms,)*
                        }
                    }

                    fn included(&self, shard: &Self::Record) -> bool {
                        match self {
                            #(#included_arms,)*
                        }
                    }
                }
            };

            let eval_arms = variants.iter().map(|(variant_name, field)| {
                let field_ty = &field.ty;
                quote! {
                    #name::#variant_name(x) => <#field_ty as p3_air::Air<AB>>::eval(x, builder)
                }
            });

            // Attach an extra generic AB : crate::air::SP1AirBuilder to the generics of the enum
            let generics = &ast.generics;
            let mut new_generics = generics.clone();
            new_generics
                .params
                .push(syn::parse_quote! { AB: p3_air::PairBuilder + #builder_path });

            let (air_impl_generics, _, _) = new_generics.split_for_impl();

            let mut new_generics = generics.clone();
            let where_clause = new_generics.make_where_clause();
            if eval_trait_bound.is_some() {
                let predicate: WherePredicate = syn::parse_str(&eval_trait_bound.unwrap()).unwrap();
                where_clause.predicates.push(predicate);
            }

            let air = quote! {
                impl #air_impl_generics p3_air::Air<AB> for #name #ty_generics #where_clause {
                    fn eval(&self, builder: &mut AB) {
                        match self {
                            #(#eval_arms,)*
                        }
                    }
                }
            };

            quote! {
                #base_air

                #machine_air

                #air
            }
            .into()
        }
        Data::Union(_) => unimplemented!("Unions are not supported"),
    }
}

#[proc_macro_attribute]
pub fn cycle_tracker(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    let visibility = &input.vis;
    let name = &input.sig.ident;
    let inputs = &input.sig.inputs;
    let output = &input.sig.output;
    let block = &input.block;
    let generics = &input.sig.generics;
    let where_clause = &input.sig.generics.where_clause;

    let result = quote! {
        #visibility fn #name #generics (#inputs) #output #where_clause {
            sphinx_lib::unconstrained! {
                println!("cycle-tracker-start: {}", stringify!(#name));
            }
            let result = (|| #block)();
            sphinx_lib::unconstrained! {
                println!("cycle-tracker-end: {}", stringify!(#name));
            }
            result
        }
    };

    result.into()
}

fn find_sphinx_core_path(attrs: &[syn::Attribute]) -> syn::Ident {
    for attr in attrs {
        if attr.path.is_ident("sphinx_core_path") {
            if let Ok(syn::Meta::NameValue(meta)) = attr.parse_meta() {
                if let syn::Lit::Str(lit_str) = &meta.lit {
                    return syn::Ident::new(&lit_str.value(), lit_str.span());
                }
            }
        }
    }
    syn::Ident::new("crate", proc_macro2::Span::call_site())
}

fn find_execution_record_path(attrs: &[syn::Attribute]) -> syn::Path {
    for attr in attrs {
        if attr.path.is_ident("execution_record_path") {
            if let Ok(syn::Meta::NameValue(meta)) = attr.parse_meta() {
                if let syn::Lit::Str(lit_str) = &meta.lit {
                    if let Ok(path) = lit_str.parse::<syn::Path>() {
                        return path;
                    }
                }
            }
        }
    }
    parse_quote!(crate::runtime::ExecutionRecord)
}

fn find_program_path(attrs: &[syn::Attribute]) -> syn::Path {
    for attr in attrs {
        if attr.path.is_ident("program_path") {
            if let Ok(syn::Meta::NameValue(meta)) = attr.parse_meta() {
                if let syn::Lit::Str(lit_str) = &meta.lit {
                    if let Ok(path) = lit_str.parse::<syn::Path>() {
                        return path;
                    }
                }
            }
        }
    }
    parse_quote!(crate::runtime::Program)
}

fn find_builder_path(attrs: &[syn::Attribute]) -> syn::Path {
    for attr in attrs {
        if attr.path.is_ident("builder_path") {
            if let Ok(syn::Meta::NameValue(meta)) = attr.parse_meta() {
                if let syn::Lit::Str(lit_str) = &meta.lit {
                    if let Ok(path) = lit_str.parse::<syn::Path>() {
                        return path;
                    }
                }
            }
        }
    }
    parse_quote!(crate::air::SphinxAirBuilder<F = F>)
}

fn find_eval_trait_bound(attrs: &[syn::Attribute]) -> Option<String> {
    for attr in attrs {
        if attr.path.is_ident("eval_trait_bound") {
            if let Ok(syn::Meta::NameValue(meta)) = attr.parse_meta() {
                if let syn::Lit::Str(lit_str) = &meta.lit {
                    return Some(lit_str.value());
                }
            }
        }
    }

    None
}
