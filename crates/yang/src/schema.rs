//! The statement parser and schema tree — RFC 7950 §6.3
//! "Statements", §7.1 "module", §7.1.5 "import", §7.1.6 "include",
//! §7.2 "submodule" (§7.2.2 belongs-to), §7.3 "typedef" (§7.3.2
//! type, §7.3.4 default), §7.4 "type", §7.5 "container", §7.6
//! "leaf" (§7.6.4 default, §7.6.5 mandatory, §7.6.3 type), §7.7
//! "leaf-list", §7.8 "list" (§7.8.2 key), §7.5.3 "must" (§7.5.4.1
//! error-message), §7.21.1 "config".
//!
//! The subset is STRICT: every statement the parser does not know is
//! an error naming the construct's RFC section, never a silent skip.
//! That is the honest shape for a subset parser — a model that needs
//! `grouping` (§7.12), `uses` (§7.13), `augment` (§7.17), `choice`
//! (§7.9), `anydata` (§7.10), `when` (§7.21.5), `feature`/
//! `if-feature` (§7.20.1/§7.20.2), `deviation` (§7.20.3),
//! `rpc`/`action`/`notification` (§7.14/§7.15/§7.16), or
//! `presence` (§7.5.5) refuses to load with a pointer to the
//! section it needs — the §Deferred ledger, machine-readable.
//!
//! Imports are simplified to single-file modules (the prompt's M1
//! rule): `import` resolves against the texts handed to
//! [`ModuleSet::build`] by module name; `revision-date` (§7.1.5.1)
//! is parsed and recorded but not used to select among revisions
//! (exactly one revision per module text — the subset's
//! simplification). Submodules parse (§7.2) and merge into their
//! including module via `include` (§7.1.6).
//!
//! `config` (§7.21.1) is inherited — a node without its own
//! `config` statement takes its parent's, and the module root
//! defaults to `config true` (§7.21.1: "if the parent node is
//! 'config true', ... the default is also 'config true'").

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::lexer::{is_identifier, is_qualified_identifier, tokenize, Token};
use crate::must::MustDef;
use crate::regex::Regex;
use crate::types::{self, InetType, IntKind, Type};

/// A schema error — line-numbered (the house shape).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SchemaError {
    #[error("line {line}: {reason}")]
    Line { line: usize, reason: String },
}

fn err(line: usize, reason: impl Into<String>) -> SchemaError {
    SchemaError::Line {
        line,
        reason: reason.into(),
    }
}

/// One statement (§6.3): `keyword [argument] (";" | "{" body "}")`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub keyword: String,
    pub arg: Option<String>,
    pub body: Vec<Statement>,
    pub line: usize,
}

/// Parses a token stream into statements.
pub fn parse_statements(input: &str) -> Result<Vec<Statement>, SchemaError> {
    let tokens = tokenize(input).map_err(|e| {
        let crate::lexer::LexError::At { line, col, reason } = e;
        err(line, format!("lexical error at {col}:{reason}"))
    })?;
    let mut pos = 0usize;
    let mut out = Vec::new();
    while pos < tokens.len() {
        let (stmt, next) = parse_statement(&tokens, pos)?;
        out.push(stmt);
        pos = next;
    }
    Ok(out)
}

fn parse_statement(
    tokens: &[crate::lexer::Spanned],
    pos: usize,
) -> Result<(Statement, usize), SchemaError> {
    let head = &tokens[pos];
    let Some(keyword) = head.token.as_arg().map(str::to_string) else {
        return Err(err(
            head.line,
            format!("expected a statement keyword, got `{}`", head.token),
        ));
    };
    if !is_identifier(&keyword) {
        return Err(err(
            head.line,
            format!("`{keyword}` is not an identifier (RFC 7950 §6.2)"),
        ));
    }
    let mut pos = pos + 1;
    let mut arg = None;
    if let Some(a) = tokens.get(pos).and_then(|t| t.token.as_arg()) {
        arg = Some(a.to_string());
        pos += 1;
    }
    match tokens.get(pos).map(|t| &t.token) {
        Some(Token::Semicolon) => Ok((
            Statement {
                keyword,
                arg,
                body: Vec::new(),
                line: head.line,
            },
            pos + 1,
        )),
        Some(Token::OpenBrace) => {
            let (body, next) = parse_body(tokens, pos + 1, head.line)?;
            Ok((
                Statement {
                    keyword,
                    arg,
                    body,
                    line: head.line,
                },
                next,
            ))
        }
        _ => Err(err(
            head.line,
            format!(
                "statement `{keyword}` must end with `;` or open a `{{}}` block (RFC 7950 §6.3)"
            ),
        )),
    }
}

fn parse_body(
    tokens: &[crate::lexer::Spanned],
    pos: usize,
    opener_line: usize,
) -> Result<(Vec<Statement>, usize), SchemaError> {
    let mut out = Vec::new();
    let mut pos = pos;
    while pos < tokens.len() {
        if tokens[pos].token == Token::CloseBrace {
            return Ok((out, pos + 1));
        }
        let (stmt, next) = parse_statement(tokens, pos)?;
        out.push(stmt);
        pos = next;
    }
    Err(err(
        opener_line,
        "statement block opened here is never closed (missing `}`)",
    ))
}

// ---- the schema model ----

/// An import binding: local prefix -> module name (§7.1.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    pub prefix: String,
    pub module: String,
    pub revision_date: Option<String>,
    pub line: usize,
}

/// A typedef (§7.3): a name, its type spec, an optional default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Typedef {
    pub name: String,
    pub spec: TypeSpec,
    pub default: Option<String>,
    pub line: usize,
}

/// A type reference with its facets, pre-resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeSpec {
    /// A built-in base type name (int8..64, string, boolean,
    /// enumeration, union, empty) with facets.
    Builtin { base: String, facets: Facets },
    /// A typedef reference — local name or `prefix:name` (§5.4's
    /// resolution), with caller facets that further restrict.
    Named { qname: String, facets: Facets },
}

/// Type facets: `range` (§9.2.4), `length` (§9.4.4), `pattern`
/// (§9.4.5, multiple AND), `enum` (§9.6.4), union member `type`
/// sub-statements (§9.12).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facets {
    pub range: Option<String>,
    pub length: Option<String>,
    pub patterns: Vec<String>,
    pub enums: Vec<String>,
    pub members: Vec<TypeSpec>,
}

/// A `must` constraint (§7.5.3) — expression text plus its
/// error-message (§7.5.4.1), parsed and evaluated by [`crate::must`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaMust {
    pub def: MustDef,
}

/// One data-node definition in the schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataDef {
    Container(ContainerDef),
    List(ListDef),
    Leaf(LeafDef),
    LeafList(LeafListDef),
}

impl DataDef {
    pub fn name(&self) -> &str {
        match self {
            DataDef::Container(c) => &c.name,
            DataDef::List(l) => &l.name,
            DataDef::Leaf(l) => &l.name,
            DataDef::LeafList(l) => &l.name,
        }
    }

    pub fn line(&self) -> usize {
        match self {
            DataDef::Container(c) => c.line,
            DataDef::List(l) => l.line,
            DataDef::Leaf(l) => l.line,
            DataDef::LeafList(l) => l.line,
        }
    }

    /// The resolved, effective `config` flag (§7.21.1, inherited).
    pub fn is_config(&self) -> bool {
        match self {
            DataDef::Container(c) => c.config,
            DataDef::List(l) => l.config,
            DataDef::Leaf(l) => l.config,
            DataDef::LeafList(l) => l.config,
        }
    }

    /// The node's `must` constraints.
    pub fn musts(&self) -> &[SchemaMust] {
        match self {
            DataDef::Container(c) => &c.musts,
            DataDef::List(l) => &l.musts,
            DataDef::Leaf(l) => &l.musts,
            DataDef::LeafList(l) => &l.musts,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerDef {
    pub name: String,
    pub config: bool,
    pub musts: Vec<SchemaMust>,
    pub children: Vec<DataDef>,
    pub description: Option<String>,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListDef {
    pub name: String,
    /// The key leaf names (§7.8.2), space-separated in the `key`
    /// argument. Every list in the subset has a key (config lists
    /// MUST, §7.8.2; state lists are not modeled).
    pub keys: Vec<String>,
    pub config: bool,
    pub musts: Vec<SchemaMust>,
    pub children: Vec<DataDef>,
    pub description: Option<String>,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafDef {
    pub name: String,
    /// The type spec as written (typedef names unresolved).
    pub spec: TypeSpec,
    /// The resolved type — `None` until [`ModuleSet::build`]'s
    /// resolution pass (which always completes or errors).
    pub resolved: Option<Type>,
    pub default: Option<String>,
    /// §7.6.5 mandatory.
    pub mandatory: bool,
    pub config: bool,
    pub musts: Vec<SchemaMust>,
    pub description: Option<String>,
    pub line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafListDef {
    pub name: String,
    pub spec: TypeSpec,
    pub resolved: Option<Type>,
    pub config: bool,
    pub musts: Vec<SchemaMust>,
    pub description: Option<String>,
    pub line: usize,
}

/// A parsed module (or submodule) header + body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module {
    pub name: String,
    pub kind: ModuleKind,
    pub prefix: String,
    pub namespace: Option<String>,
    pub revision: Option<String>,
    pub imports: Vec<Import>,
    /// `include`d submodules (§7.1.6), by name.
    pub includes: Vec<String>,
    pub typedefs: BTreeMap<String, Typedef>,
    pub data: Vec<DataDef>,
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleKind {
    Module,
    Submodule,
}

/// A set of parsed modules with imports/includes resolved and every
/// type reference resolved to a concrete [`Type`].
#[derive(Debug, Clone)]
pub struct ModuleSet {
    pub modules: BTreeMap<String, Module>,
}

/// A schema handle: the set plus the module a data tree binds to.
/// This is what [`crate::data::DataTree`] validates against.
#[derive(Debug, Clone)]
pub struct Schema {
    pub set: Arc<ModuleSet>,
    pub module: String,
}

impl Schema {
    /// The owning module's root data definitions.
    pub fn root(&self) -> &[DataDef] {
        &self.set.modules[&self.module].data
    }

    /// Finds a root-level child by name.
    pub fn root_child(&self, name: &str) -> Option<&DataDef> {
        self.root().iter().find(|d| d.name() == name)
    }
}

impl ModuleSet {
    /// Parses and resolves a set of single-file module texts. Every
    /// import/include must resolve inside the set; every type
    /// reference must resolve; duplicates are errors.
    pub fn build(texts: Vec<(String, String)>) -> Result<Arc<ModuleSet>, SchemaError> {
        let mut modules = BTreeMap::new();
        for (name, text) in texts {
            let module = parse_module_text(&name, &text)?;
            if let Some(existing) = modules.insert(module.name.clone(), module) {
                return Err(err(
                    existing.line,
                    format!(
                        "duplicate module name `{}` (a module text and its name must agree and be unique)",
                        existing.name
                    ),
                ));
            }
        }
        let mut set = ModuleSet { modules };
        set.resolve_includes()?;
        resolve_all_types(&mut set)?;
        Ok(Arc::new(set))
    }

    fn resolve_includes(&mut self) -> Result<(), SchemaError> {
        // Merge each submodule's typedefs/data into its including
        // module (§7.1.6). One include level is enough for the
        // subset (no nested submodule chains in the model set).
        let mut merged: Vec<(String, Module)> = Vec::new();
        let names: Vec<String> = self.modules.keys().cloned().collect();
        for name in names {
            let mut module = self.modules[&name].clone();
            for include in module.includes.clone() {
                let sub = self.modules.get(&include).ok_or_else(|| {
                    err(
                        module.line,
                        format!("include `{include}` does not resolve (RFC 7950 §7.1.6)"),
                    )
                })?;
                if sub.kind != ModuleKind::Submodule {
                    return Err(err(
                        module.line,
                        format!(
                            "include `{include}` is not a submodule (§7.1.6 includes submodules)"
                        ),
                    ));
                }
                if sub.prefix != module.name {
                    return Err(err(
                        sub.line,
                        format!(
                            "submodule `{include}` belongs-to `{}`, included by `{}` (§7.2.2)",
                            sub.prefix, module.name
                        ),
                    ));
                }
                for (tname, typedef) in &sub.typedefs {
                    if module
                        .typedefs
                        .insert(tname.clone(), typedef.clone())
                        .is_some()
                    {
                        return Err(err(
                            typedef.line,
                            format!("typedef `{tname}` collides after include merge"),
                        ));
                    }
                }
                module.data.extend(sub.data.iter().cloned());
            }
            module.includes.clear();
            merged.push((name, module));
        }
        for (name, module) in merged {
            self.modules.insert(name, module);
        }
        Ok(())
    }

    /// A schema bound to one module of the set.
    pub fn schema(self: &Arc<Self>, module: &str) -> Result<Schema, SchemaError> {
        let module_def = self
            .modules
            .get(module)
            .ok_or_else(|| err(0, format!("module `{module}` is not in the set")))?;
        if module_def.kind != ModuleKind::Module {
            return Err(err(
                module_def.line,
                "bind a schema to a module, not a submodule",
            ));
        }
        Ok(Schema {
            set: Arc::clone(self),
            module: module.to_string(),
        })
    }
}

/// Parses one module/submodule text (the file name is used only for
/// error messages; the statement's own name argument wins).
pub fn parse_module_text(_file: &str, text: &str) -> Result<Module, SchemaError> {
    let mut stmts = parse_statements(text)?;
    if stmts.len() != 1 {
        return Err(err(
            stmts.first().map(|s| s.line).unwrap_or(1),
            "a YANG file is exactly one `module` or `submodule` statement",
        ));
    }
    let root = stmts.remove(0);
    let kind = match root.keyword.as_str() {
        "module" => ModuleKind::Module,
        "submodule" => ModuleKind::Submodule,
        other => {
            return Err(err(
                root.line,
                format!("expected `module` or `submodule`, got `{other}` (RFC 7950 §7.1/§7.2)"),
            ));
        }
    };
    let name = root
        .arg
        .clone()
        .ok_or_else(|| err(root.line, "module statement needs a name (§7.1)"))?;
    if !is_identifier(&name) {
        return Err(err(
            root.line,
            format!("module name `{name}` is not an identifier (§6.2)"),
        ));
    }
    let mut module = Module {
        name,
        kind,
        prefix: String::new(),
        namespace: None,
        revision: None,
        imports: Vec::new(),
        includes: Vec::new(),
        typedefs: BTreeMap::new(),
        data: Vec::new(),
        line: root.line,
    };
    for st in &root.body {
        match st.keyword.as_str() {
            "yang-version" => {
                if st.arg.as_deref() != Some("1.1") {
                    return Err(err(
                        st.line,
                        format!(
                            "only yang-version 1.1 is supported (RFC 7950 IS YANG 1.1), got `{}`",
                            st.arg.as_deref().unwrap_or("")
                        ),
                    ));
                }
            }
            "namespace" => {
                if module.kind != ModuleKind::Module {
                    return Err(err(st.line, "submodules have no namespace (§7.2)"));
                }
                module.namespace = Some(
                    st.arg
                        .clone()
                        .ok_or_else(|| err(st.line, "namespace needs a URI argument (§7.1.3)"))?,
                );
            }
            "prefix" => {
                module.prefix = st
                    .arg
                    .clone()
                    .ok_or_else(|| err(st.line, "prefix needs an argument (§7.1.4)"))?;
            }
            "import" => {
                let target = st
                    .arg
                    .clone()
                    .ok_or_else(|| err(st.line, "import needs a module name (§7.1.5)"))?;
                let mut prefix = None;
                let mut revision_date = None;
                for sub in &st.body {
                    match sub.keyword.as_str() {
                        "prefix" => prefix = sub.arg.clone(),
                        "revision-date" => revision_date = sub.arg.clone(),
                        "description" | "reference" => {}
                        other => {
                            return Err(err(
                                sub.line,
                                format!("`{other}` is not an import sub-statement (§7.1.5)"),
                            ));
                        }
                    }
                }
                let prefix = prefix.ok_or_else(|| {
                    err(st.line, "import requires a prefix sub-statement (§7.1.5)")
                })?;
                module.imports.push(Import {
                    prefix,
                    module: target,
                    revision_date,
                    line: st.line,
                });
            }
            "include" => {
                let target = st
                    .arg
                    .clone()
                    .ok_or_else(|| err(st.line, "include needs a submodule name (§7.1.6)"))?;
                module.includes.push(target);
            }
            "belongs-to" => {
                if module.kind != ModuleKind::Submodule {
                    return Err(err(st.line, "`belongs-to` is submodule-only (§7.2.2)"));
                }
                module.prefix = st.arg.clone().ok_or_else(|| {
                    err(st.line, "belongs-to needs the owning module name (§7.2.2)")
                })?;
                for sub in &st.body {
                    match sub.keyword.as_str() {
                        "prefix" => {}
                        other => {
                            return Err(err(
                                sub.line,
                                format!("`{other}` is not a belongs-to sub-statement (§7.2.2)"),
                            ));
                        }
                    }
                }
            }
            "revision" => {
                let rev = st
                    .arg
                    .clone()
                    .ok_or_else(|| err(st.line, "revision needs a date (§7.1.9)"))?;
                if module
                    .revision
                    .as_deref()
                    .map(|r| r < rev.as_str())
                    .unwrap_or(true)
                {
                    module.revision = Some(rev);
                }
            }
            "typedef" => {
                let typedef = parse_typedef(st)?;
                module.typedefs.insert(typedef.name.clone(), typedef);
            }
            "container" | "list" | "leaf" | "leaf-list" => {
                module.data.push(parse_data_def(st, true)?);
            }
            "description" | "reference" | "organization" | "contact" | "copyright" => {}
            "status" => {}
            other => {
                return Err(err(
                    st.line,
                    format!(
                        "`{other}` is not in the Rouster YANG subset (RFC 7950 §{other} is §Deferred; supported: module/submodule header, import/include, typedef, container, list, leaf, leaf-list)"
                    ),
                ));
            }
        }
    }
    if module.prefix.is_empty() {
        return Err(err(module.line, "module requires a prefix (§7.1.4)"));
    }
    if module.namespace.is_none() && module.kind == ModuleKind::Module {
        return Err(err(module.line, "module requires a namespace (§7.1.3)"));
    }
    Ok(module)
}

fn parse_typedef(st: &Statement) -> Result<Typedef, SchemaError> {
    let name = st
        .arg
        .clone()
        .ok_or_else(|| err(st.line, "typedef needs a name (§7.3)"))?;
    if !is_identifier(&name) {
        return Err(err(
            st.line,
            format!("typedef name `{name}` is not an identifier (§6.2)"),
        ));
    }
    let mut spec = None;
    let mut default = None;
    for sub in &st.body {
        match sub.keyword.as_str() {
            "type" => spec = Some(parse_type(sub)?),
            "default" => default = sub.arg.clone(),
            "description" | "reference" | "status" | "units" => {}
            other => {
                return Err(err(
                    sub.line,
                    format!("`{other}` is not a typedef sub-statement (§7.3)"),
                ));
            }
        }
    }
    let spec = spec.ok_or_else(|| err(st.line, "typedef requires a type (§7.3.2)"))?;
    Ok(Typedef {
        name,
        spec,
        default,
        line: st.line,
    })
}

fn parse_data_def(st: &Statement, parent_config: bool) -> Result<DataDef, SchemaError> {
    let name = st
        .arg
        .clone()
        .ok_or_else(|| err(st.line, format!("`{}` needs a name", st.keyword)))?;
    if !is_identifier(&name) {
        return Err(err(
            st.line,
            format!("node name `{name}` is not an identifier (§6.2)"),
        ));
    }
    // §7.21.1: config is inherited — this node's own statement, if
    // present, else the parent's. Children parse against the
    // effective value so ordering inside the body cannot matter.
    let own_config = st
        .body
        .iter()
        .find(|sub| sub.keyword == "config")
        .and_then(|sub| match sub.arg.as_deref() {
            Some("true") => Some(true),
            Some("false") => Some(false),
            // A malformed value is surfaced as an error below, when
            // the same statement is parsed in the main loop.
            _ => None,
        });
    let config = own_config.unwrap_or(parent_config);
    let mut musts = Vec::new();
    let mut description = None;
    let mut children = Vec::new();
    let mut keys: Vec<String> = Vec::new();
    let mut spec: Option<TypeSpec> = None;
    let mut default = None;
    let mut mandatory = false;
    for sub in &st.body {
        match sub.keyword.as_str() {
            "config" => match sub.arg.as_deref() {
                Some("true") | Some("false") => {}
                other => {
                    return Err(err(
                        sub.line,
                        format!("config takes true|false, got `{other:?}` (§7.21.1)"),
                    ));
                }
            },
            "must" => musts.push(SchemaMust {
                def: parse_must(sub)?,
            }),
            "description" => description = sub.arg.clone(),
            "reference" | "status" => {}
            "container" | "list" | "leaf" | "leaf-list" => {
                if st.keyword != "container" && st.keyword != "list" {
                    return Err(err(
                        sub.line,
                        format!("`{}` cannot hold data children (§7.6/§7.7)", st.keyword),
                    ));
                }
                children.push(parse_data_def(sub, config)?);
            }
            "key" if st.keyword == "list" => {
                let arg = sub
                    .arg
                    .clone()
                    .ok_or_else(|| err(sub.line, "key needs leaf names (§7.8.2)"))?;
                keys = arg
                    .split_whitespace()
                    .map(str::to_string)
                    .collect::<Vec<_>>();
            }
            "type" if st.keyword == "leaf" || st.keyword == "leaf-list" => {
                spec = Some(parse_type(sub)?);
            }
            "default" if st.keyword == "leaf" => default = sub.arg.clone(),
            "mandatory" if st.keyword == "leaf" => {
                mandatory = match sub.arg.as_deref() {
                    Some("true") => true,
                    Some("false") => false,
                    other => {
                        return Err(err(
                            sub.line,
                            format!("mandatory takes true|false, got `{other:?}` (§7.6.5)"),
                        ));
                    }
                };
            }
            other => {
                return Err(err(
                    sub.line,
                    format!(
                        "`{other}` is not a `{}` sub-statement in the subset (RFC 7950 §{other}: §Deferred)",
                        st.keyword
                    ),
                ));
            }
        }
    }
    match st.keyword.as_str() {
        "container" => Ok(DataDef::Container(ContainerDef {
            name,
            config,
            musts,
            children,
            description,
            line: st.line,
        })),
        "list" => {
            if keys.is_empty() {
                return Err(err(
                    st.line,
                    "the subset requires a key on every list (RFC 7950 §7.8.2: config lists MUST have one; state lists are not modeled)",
                ));
            }
            Ok(DataDef::List(ListDef {
                name,
                keys,
                config,
                musts,
                children,
                description,
                line: st.line,
            }))
        }
        "leaf" => Ok(DataDef::Leaf(LeafDef {
            name,
            spec: spec.ok_or_else(|| err(st.line, "leaf requires a type (§7.6.3)"))?,
            resolved: None,
            default,
            mandatory,
            config,
            musts,
            description,
            line: st.line,
        })),
        "leaf-list" => {
            if default.is_some() {
                // `default` was not captured for leaf-lists above;
                // unreachable, kept for clarity.
            }
            Ok(DataDef::LeafList(LeafListDef {
                name,
                spec: spec.ok_or_else(|| err(st.line, "leaf-list requires a type (§7.7.3)"))?,
                resolved: None,
                config,
                musts,
                description,
                line: st.line,
            }))
        }
        other => Err(err(st.line, format!("`{other}` is not a data statement"))),
    }
}

fn parse_must(st: &Statement) -> Result<MustDef, SchemaError> {
    let expr = st
        .arg
        .clone()
        .ok_or_else(|| err(st.line, "must needs an expression (§7.5.3)"))?;
    let mut error_message = None;
    for sub in &st.body {
        match sub.keyword.as_str() {
            "error-message" => error_message = sub.arg.clone(),
            "error-app-tag" | "description" | "reference" => {}
            other => {
                return Err(err(
                    sub.line,
                    format!("`{other}` is not a must sub-statement (§7.5.4)"),
                ));
            }
        }
    }
    // Parse eagerly: a must expression that the evaluator's grammar
    // cannot accept is a schema error, not a runtime surprise.
    let def = crate::must::MustDef::parse(&expr, error_message).map_err(|e| err(st.line, e))?;
    Ok(def)
}

/// Parses a `type` statement (§7.4): the base name plus facet body.
fn parse_type(st: &Statement) -> Result<TypeSpec, SchemaError> {
    let base = st
        .arg
        .clone()
        .ok_or_else(|| err(st.line, "type needs a base name (§7.4)"))?;
    if !is_qualified_identifier(&base) {
        return Err(err(
            st.line,
            format!("type name `{base}` is not a (qualified) identifier (§6.2)"),
        ));
    }
    let mut facets = Facets::default();
    for sub in &st.body {
        match sub.keyword.as_str() {
            "range" => facets.range = sub.arg.clone(),
            "length" => facets.length = sub.arg.clone(),
            "pattern" => {
                let p = sub
                    .arg
                    .clone()
                    .ok_or_else(|| err(sub.line, "pattern needs an argument (§9.4.5)"))?;
                facets.patterns.push(p);
            }
            "enum" => {
                let name = sub
                    .arg
                    .clone()
                    .ok_or_else(|| err(sub.line, "enum needs a name (§9.6.4)"))?;
                facets.enums.push(name);
            }
            "type" => facets.members.push(parse_type(sub)?),
            "fraction-digits" => {
                return Err(err(
                    sub.line,
                    "decimal64 and fraction-digits are §Deferred (RFC 7950 §9.3)",
                ));
            }
            "path" => {
                return Err(err(
                    sub.line,
                    "leafref and path are §Deferred (RFC 7950 §9.9)",
                ));
            }
            "require-instance" | "modifier" => {
                return Err(err(
                    sub.line,
                    format!("`{}` is §Deferred (RFC 7950 §9.9/§9.4.6)", sub.keyword),
                ));
            }
            other => {
                return Err(err(
                    sub.line,
                    format!("`{other}` is not a type facet in the subset (§7.4.1)"),
                ));
            }
        }
    }
    if is_qualified_identifier(&base) && base.contains(':') {
        Ok(TypeSpec::Named {
            qname: base,
            facets,
        })
    } else if types::builtin(&base).is_some()
        || matches!(
            base.as_str(),
            "decimal64" | "binary" | "bits" | "leafref" | "identityref" | "instance-identifier"
        )
    {
        match base.as_str() {
            "decimal64" => return Err(err(st.line, "decimal64 is §Deferred (RFC 7950 §9.3)")),
            "binary" => return Err(err(st.line, "binary is §Deferred (RFC 7950 §9.8)")),
            "bits" => return Err(err(st.line, "bits are §Deferred (RFC 7950 §9.7)")),
            "leafref" => return Err(err(st.line, "leafref is §Deferred (RFC 7950 §9.9)")),
            "identityref" => {
                return Err(err(st.line, "identityref is §Deferred (RFC 7950 §9.10)"));
            }
            "instance-identifier" => {
                return Err(err(
                    st.line,
                    "instance-identifier is §Deferred (RFC 7950 §9.13)",
                ));
            }
            _ => {}
        }
        Ok(TypeSpec::Builtin { base, facets })
    } else {
        // A bare name that is not a builtin is a local typedef ref.
        Ok(TypeSpec::Named {
            qname: base,
            facets,
        })
    }
}

// ---- type resolution (§5.4's name resolution, simplified) ----

fn resolve_all_types(set: &mut ModuleSet) -> Result<(), SchemaError> {
    let names: Vec<String> = set.modules.keys().cloned().collect();
    for name in names {
        let mut module = set.modules[&name].clone();
        let imports: BTreeMap<String, String> = module
            .imports
            .iter()
            .map(|i| (i.prefix.clone(), i.module.clone()))
            .collect();
        let mut data = module.data.clone();
        for def in data.iter_mut() {
            resolve_data_def(def, &module, &imports, set, 0)?;
        }
        module.data = data;
        set.modules.insert(name, module);
    }
    Ok(())
}

fn resolve_data_def(
    def: &mut DataDef,
    module: &Module,
    imports: &BTreeMap<String, String>,
    frozen: &ModuleSet,
    depth: usize,
) -> Result<(), SchemaError> {
    if depth > 32 {
        return Err(err(def.line(), "schema nesting deeper than 32 levels"));
    }
    match def {
        DataDef::Container(c) => {
            for child in c.children.iter_mut() {
                resolve_data_def(child, module, imports, frozen, depth + 1)?;
            }
        }
        DataDef::List(l) => {
            // §7.8.2: every key leaf must exist as a child.
            for key in &l.keys {
                if !l.children.iter().any(|c| match c {
                    DataDef::Leaf(leaf) => &leaf.name == key,
                    _ => false,
                }) {
                    return Err(err(
                        l.line,
                        format!(
                            "key leaf `{key}` is not a child of list `{}` (§7.8.2)",
                            l.name
                        ),
                    ));
                }
            }
            for child in l.children.iter_mut() {
                resolve_data_def(child, module, imports, frozen, depth + 1)?;
            }
        }
        DataDef::Leaf(leaf) => {
            let resolved = resolve_spec(&leaf.spec, leaf.line, module, imports, frozen, 0)?;
            leaf.resolved = Some(resolved);
        }
        DataDef::LeafList(ll) => {
            let resolved = resolve_spec(&ll.spec, ll.line, module, imports, frozen, 0)?;
            ll.resolved = Some(resolved);
        }
    }
    Ok(())
}

fn resolve_spec(
    spec: &TypeSpec,
    line: usize,
    module: &Module,
    imports: &BTreeMap<String, String>,
    frozen: &ModuleSet,
    depth: usize,
) -> Result<Type, SchemaError> {
    if depth > 16 {
        return Err(err(line, "typedef derivation deeper than 16 levels"));
    }
    match spec {
        TypeSpec::Builtin { base, facets } => build_builtin(base, facets, line),
        TypeSpec::Named { qname, facets } => {
            // The inet: prefix is a built-in pseudo-module: RFC 6991
            // §3.2's typedefs are re-implemented natively in
            // `types.rs` (std parsing — stricter-equal to the RFC's
            // patterns; the patterns themselves use XSD features the
            // mini engine deliberately lacks).
            if let Some(inet_name) = qname.strip_prefix("inet:") {
                let inet = InetType::from_name(inet_name).ok_or_else(|| {
                    err(
                        line,
                        format!("`{qname}` is not an inet type (RFC 6991 §3.2)"),
                    )
                })?;
                return Ok(Type::Inet(inet));
            }
            let (def_module_name, tname) = match qname.split_once(':') {
                Some((prefix, name)) => {
                    let target = imports.get(prefix).ok_or_else(|| {
                        err(line, format!("prefix `{prefix}` is not imported (§7.1.5)"))
                    })?;
                    (target.clone(), name.to_string())
                }
                None => (module.name.clone(), qname.clone()),
            };
            let def_module = frozen.modules.get(&def_module_name).ok_or_else(|| {
                err(
                    line,
                    format!("module `{def_module_name}` is not in the set"),
                )
            })?;
            let typedef = def_module.typedefs.get(&tname).ok_or_else(|| {
                err(
                    line,
                    format!("typedef `{tname}` not found in module `{def_module_name}` (§5.4)"),
                )
            })?;
            let base = resolve_spec(
                &typedef.spec,
                typedef.line,
                def_module,
                &imports_for(def_module),
                frozen,
                depth + 1,
            )?;
            restrict(&base, facets, line)
        }
    }
}

fn imports_for(module: &Module) -> BTreeMap<String, String> {
    module
        .imports
        .iter()
        .map(|i| (i.prefix.clone(), i.module.clone()))
        .collect()
}

/// Applies caller facets over a resolved (possibly typedef-derived)
/// type — restrictions can only narrow (§7.3's derivation rules).
fn restrict(base: &Type, facets: &Facets, line: usize) -> Result<Type, SchemaError> {
    let mut out = base.clone();
    match (&mut out, facets) {
        (Type::Int(kind, ranges), f) if f.range.is_some() => {
            let extra =
                types::parse_range(f.range.as_deref().unwrap(), *kind).map_err(|e| err(line, e))?;
            let merged = if ranges.is_empty() {
                extra
            } else {
                intersect_ranges(ranges, &extra)
            };
            if merged.is_empty() {
                return Err(err(line, "range restriction narrows to nothing (§9.2.4)"));
            }
            *ranges = merged;
        }
        (Type::Str { lengths, patterns }, f) => {
            if let Some(len) = &f.length {
                let extra = types::parse_length(len).map_err(|e| err(line, e))?;
                lengths.extend(extra);
            }
            for p in &f.patterns {
                let compiled = Regex::new(p).map_err(|e| err(line, e.to_string()))?;
                patterns.push(compiled);
            }
        }
        (Type::Enum(_), f) if !f.enums.is_empty() => {
            // §9.6.2: restriction may only REMOVE enum values.
            let wanted: std::collections::BTreeSet<String> = f.enums.iter().cloned().collect();
            let Type::Enum(existing) = base else {
                unreachable!()
            };
            let narrowed: std::collections::BTreeSet<String> =
                existing.intersection(&wanted).cloned().collect();
            if narrowed.is_empty() {
                return Err(err(
                    line,
                    "enumeration restriction removes every name (§9.6.2)",
                ));
            }
            out = Type::Enum(narrowed);
        }
        (Type::Union(_), f) if !f.members.is_empty() => {
            return Err(err(
                line,
                "union restriction with member types is not supported (§9.12)",
            ));
        }
        _ => {
            // Facets on a base that takes none (e.g. range on a
            // string) — reject rather than silently drop.
            if facets.range.is_some() {
                return Err(err(line, "range applies to numeric types only (§9.2.4)"));
            }
            if facets.length.is_some() || !facets.patterns.is_empty() {
                return Err(err(
                    line,
                    "length/pattern apply to string types only (§9.4.4/§9.4.5)",
                ));
            }
            if !facets.enums.is_empty() {
                return Err(err(line, "enum applies to enumerations only (§9.6.4)"));
            }
        }
    }
    Ok(out)
}

fn intersect_ranges(a: &[(i128, i128)], b: &[(i128, i128)]) -> Vec<(i128, i128)> {
    let mut out = Vec::new();
    for (alo, ahi) in a {
        for (blo, bhi) in b {
            let lo = (*alo).max(*blo);
            let hi = (*ahi).min(*bhi);
            if lo <= hi {
                out.push((lo, hi));
            }
        }
    }
    out.sort();
    out
}

fn build_builtin(base: &str, facets: &Facets, line: usize) -> Result<Type, SchemaError> {
    if let Some(kind) = IntKind::from_name(base) {
        let mut ranges = Vec::new();
        if let Some(arg) = &facets.range {
            ranges = types::parse_range(arg, kind).map_err(|e| err(line, e))?;
        }
        return Ok(Type::Int(kind, ranges));
    }
    match base {
        "string" => {
            let mut lengths = Vec::new();
            if let Some(arg) = &facets.length {
                lengths = types::parse_length(arg).map_err(|e| err(line, e))?;
            }
            let mut patterns = Vec::new();
            for p in &facets.patterns {
                patterns.push(Regex::new(p).map_err(|e| err(line, e.to_string()))?);
            }
            Ok(Type::Str { lengths, patterns })
        }
        "boolean" => {
            reject_facets(facets, line)?;
            Ok(Type::Boolean)
        }
        "enumeration" => {
            if facets.enums.is_empty() {
                return Err(err(line, "enumeration needs enum sub-statements (§9.6.4)"));
            }
            reject_other_facets(facets, line, "enumeration")?;
            Ok(Type::Enum(facets.enums.iter().cloned().collect()))
        }
        "union" => {
            if facets.members.is_empty() {
                return Err(err(line, "union needs member type sub-statements (§9.12)"));
            }
            reject_other_facets(facets, line, "union")?;
            // Members resolve later through the Named path when they
            // reference typedefs; builtins resolve here.
            let mut alts = Vec::new();
            for member in &facets.members {
                alts.push(build_spec(member, line)?);
            }
            Ok(Type::Union(alts))
        }
        "empty" => {
            reject_facets(facets, line)?;
            Ok(Type::Empty)
        }
        other => Err(err(
            line,
            format!("type `{other}` is not in the subset (§Deferred; see crate docs)"),
        )),
    }
}

/// Union member specs: builtin bases only (a union of inet/enum/
/// string/int is the modeled shape; typedef refs inside unions are
/// §Deferred — resolve_spec's Arc dance is not worth it yet).
fn build_spec(spec: &TypeSpec, line: usize) -> Result<Type, SchemaError> {
    match spec {
        TypeSpec::Builtin { base, facets } => build_builtin(base, facets, line),
        TypeSpec::Named { qname, .. } => {
            if let Some(inet_name) = qname.strip_prefix("inet:") {
                let inet = InetType::from_name(inet_name).ok_or_else(|| {
                    err(
                        line,
                        format!("`{qname}` is not an inet type (RFC 6991 §3.2)"),
                    )
                })?;
                return Ok(Type::Inet(inet));
            }
            Err(err(
                line,
                format!(
                    "typedef references inside unions are §Deferred: `{qname}` (spell the builtin out)"
                ),
            ))
        }
    }
}

fn reject_facets(facets: &Facets, line: usize) -> Result<(), SchemaError> {
    if facets.range.is_some() {
        return Err(err(line, "range does not apply to this type (§9.2.4)"));
    }
    if facets.length.is_some() {
        return Err(err(line, "length applies to strings only (§9.4.4)"));
    }
    if !facets.patterns.is_empty() {
        return Err(err(line, "pattern applies to strings only (§9.4.5)"));
    }
    if !facets.enums.is_empty() {
        return Err(err(line, "enum applies to enumerations only (§9.6.4)"));
    }
    if !facets.members.is_empty() {
        return Err(err(line, "member types apply to unions only (§9.12)"));
    }
    Ok(())
}

fn reject_other_facets(facets: &Facets, line: usize, kind: &str) -> Result<(), SchemaError> {
    if facets.range.is_some() {
        return Err(err(
            line,
            format!("range does not apply to {kind} (§9.2.4)"),
        ));
    }
    if facets.length.is_some() {
        return Err(err(
            line,
            format!("length does not apply to {kind} (§9.4.4)"),
        ));
    }
    if !facets.patterns.is_empty() {
        return Err(err(
            line,
            format!("pattern does not apply to {kind} (§9.4.5)"),
        ));
    }
    if !facets.enums.is_empty() && kind != "enumeration" {
        return Err(err(line, format!("enum does not apply to {kind} (§9.6.4)")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(text: &str) -> Result<Module, SchemaError> {
        parse_module_text("test.yang", text)
    }

    fn mini_module(extra: &str) -> String {
        format!(
            "module m {{\n  yang-version 1.1;\n  namespace \"urn:x:m\";\n  prefix m;\n{extra}}}\n"
        )
    }

    #[test]
    fn parses_module_header_and_one_container() {
        let m = module(&mini_module(
            "  container interfaces {\n    list interface {\n      key \"name\";\n      leaf name { type string; }\n    }\n  }\n",
        ))
        .unwrap();
        assert_eq!(m.name, "m");
        assert_eq!(m.prefix, "m");
        assert_eq!(m.namespace.as_deref(), Some("urn:x:m"));
        assert_eq!(m.data.len(), 1);
        let DataDef::Container(c) = &m.data[0] else {
            panic!("top-level statement should be a container");
        };
        assert_eq!(c.name, "interfaces");
        assert!(matches!(c.children[0], DataDef::List(_)));
    }

    #[test]
    fn golden_container_list_leaf() {
        let m = module(&mini_module(
            "  container interfaces {\n    list interface {\n      key \"name\";\n      leaf name { type string; }\n      leaf mtu { type uint16 { range 1280..9216; } }\n    }\n  }\n",
        ))
        .unwrap();
        let DataDef::Container(c) = &m.data[0] else {
            panic!()
        };
        assert_eq!(c.name, "interfaces");
        let DataDef::List(l) = &c.children[0] else {
            panic!()
        };
        assert_eq!(l.keys, vec!["name".to_string()]);
        let DataDef::Leaf(mtu) = &l.children[1] else {
            panic!()
        };
        assert!(mtu.resolved.is_none()); // resolution is ModuleSet's pass
    }

    #[test]
    fn config_is_inherited_and_overridable() {
        let set = ModuleSet::build(vec![(
            "m".into(),
            mini_module(
                "  container oper {\n    config false;\n    leaf counters { type string; }\n  }\n  container cfg {\n    leaf a { type string; }\n  }\n",
            ),
        )])
        .unwrap();
        assert!(!set.modules["m"].data[0].is_config());
        assert!(set.modules["m"].data[1].is_config());
    }

    #[test]
    fn typedef_derivation_with_facet_narrowing_resolves() {
        let set = ModuleSet::build(vec![(
            "m".into(),
            mini_module(
                "  typedef pct { type uint8 { range 0..100; } }\n  leaf load { type pct { range 10..90; } }\n  leaf plain { type pct; }\n",
            ),
        )])
        .unwrap();
        let m = &set.modules["m"];
        let DataDef::Leaf(load) = &m.data[0] else {
            panic!()
        };
        let Type::Int(_, ranges) = load.resolved.as_ref().unwrap() else {
            panic!()
        };
        assert_eq!(ranges, &vec![(10, 90)]);
        let DataDef::Leaf(plain) = &m.data[1] else {
            panic!()
        };
        let Type::Int(_, ranges2) = plain.resolved.as_ref().unwrap() else {
            panic!()
        };
        assert_eq!(ranges2, &vec![(0, 100)]);
    }

    #[test]
    fn imports_resolve_types_across_modules() {
        let common = "module rouster-common {\n  yang-version 1.1;\n  namespace \"urn:rouster:common\";\n  prefix rc;\n  typedef area-id { type string { pattern \"(0|[1-9][0-9]*)(\\\\.(0|[1-9][0-9]*))(\\\\.(0|[1-9][0-9]*))(\\\\.(0|[1-9][0-9]*))\"; } }\n}\n";
        let user = "module user {\n  yang-version 1.1;\n  namespace \"urn:x\";\n  prefix u;\n  import rouster-common { prefix rc; }\n  leaf area { type rc:area-id; }\n}\n";
        let set = ModuleSet::build(vec![
            ("common.yang".into(), common.into()),
            ("user.yang".into(), user.into()),
        ])
        .unwrap();
        let m = &set.modules["user"];
        let DataDef::Leaf(area) = &m.data[0] else {
            panic!()
        };
        let t = area.resolved.as_ref().unwrap();
        assert!(t.check("0.0.0.0").is_ok());
        assert!(t.check("nope").is_err());
    }

    #[test]
    fn include_merges_submodule_typedefs_and_data() {
        let sub = "submodule extra {\n  belongs-to m { prefix m; }\n  typedef ifname { type string { length 1..15; } }\n  leaf probe { type ifname; }\n}\n";
        let main = "module m {\n  yang-version 1.1;\n  namespace \"urn:x\";\n  prefix m;\n  include extra;\n  leaf direct { type ifname; }\n}\n";
        let set = ModuleSet::build(vec![
            ("extra.yang".into(), sub.into()),
            ("m.yang".into(), main.into()),
        ])
        .unwrap();
        assert_eq!(set.modules["m"].data.len(), 2);
        let DataDef::Leaf(direct) = &set.modules["m"].data[0] else {
            panic!()
        };
        assert!(direct.resolved.as_ref().unwrap().check("eth0").is_ok());
        assert!(direct.resolved.as_ref().unwrap().check("").is_err());
    }

    #[test]
    fn inet_types_resolve_through_the_pseudo_prefix() {
        let set = ModuleSet::build(vec![(
            "m".into(),
            mini_module(
                "  leaf peer { type inet:ipv4-address; }\n  leaf net { type inet:ip-prefix; }\n",
            ),
        )])
        .unwrap();
        let m = &set.modules["m"];
        let DataDef::Leaf(peer) = &m.data[0] else {
            panic!()
        };
        assert!(peer.resolved.as_ref().unwrap().check("192.0.2.1").is_ok());
    }

    // ---- malformed-input suite ----

    #[test]
    fn missing_namespace_prefix_and_bad_version_are_errors() {
        assert!(module("module x {\n  prefix x;\n}\n").is_err()); // no namespace
        assert!(module("module x {\n  namespace \"urn:x\";\n}\n").is_err()); // no prefix
        assert!(
            module("module x {\n  yang-version 1;\n  namespace \"urn:x\";\n  prefix x;\n}\n")
                .is_err()
        );
    }

    #[test]
    fn unknown_statements_name_their_rfc_section() {
        let e = module(&mini_module("  grouping g { leaf x { type string; } }\n")).unwrap_err();
        assert!(e.to_string().contains("grouping"), "{e}");
        assert!(e.to_string().contains("§Deferred"), "{e}");
        let e2 = module(&mini_module("  container c {\n    presence true;\n  }\n")).unwrap_err();
        assert!(e2.to_string().contains("presence"), "{e2}");
    }

    #[test]
    fn key_leaf_must_exist() {
        let e = ModuleSet::build(vec![(
            "m".into(),
            mini_module("  list peers {\n    key \"addr\";\n    leaf name { type string; }\n  }\n"),
        )])
        .unwrap_err();
        assert!(e.to_string().contains("key leaf `addr`"), "{e}");
    }

    #[test]
    fn list_without_key_is_refused() {
        let e = module(&mini_module(
            "  list peers {\n    leaf name { type string; }\n  }\n",
        ))
        .unwrap_err();
        assert!(e.to_string().contains("§7.8.2"), "{e}");
    }

    #[test]
    fn unterminated_block_names_the_opener() {
        let e = module(&mini_module(
            "  container c {\n    leaf x { type string; }\n",
        ))
        .unwrap_err();
        assert!(e.to_string().contains("never closed"), "{e}");
    }

    #[test]
    fn unresolvable_import_is_an_error() {
        let e = ModuleSet::build(vec![(
            "m".into(),
            mini_module("  import nope { prefix n; }\n  leaf x { type n:thing; }\n"),
        )])
        .unwrap_err();
        assert!(e.to_string().contains("nope"), "{e}");
    }

    #[test]
    fn duplicate_module_names_are_refused() {
        let text = mini_module("");
        let e = ModuleSet::build(vec![
            ("a.yang".into(), text.clone()),
            ("b.yang".into(), text),
        ])
        .unwrap_err();
        assert!(e.to_string().contains("duplicate module"), "{e}");
    }

    #[test]
    fn enumeration_narrowing_and_empty_narrowing() {
        let set = ModuleSet::build(vec![(
            "m".into(),
            mini_module(
                "  typedef mode { type enumeration { enum strict; enum loose; enum fp; } }\n  leaf m1 { type mode { enum strict; } }\n",
            ),
        )])
        .unwrap();
        let m = &set.modules["m"];
        let DataDef::Leaf(m1) = &m.data[0] else {
            panic!()
        };
        let t = m1.resolved.as_ref().unwrap();
        assert!(t.check("strict").is_ok());
        assert!(t.check("loose").is_err());
        // Removing every name refuses the schema.
        assert!(ModuleSet::build(vec![(
            "m".into(),
            mini_module("  typedef mode { type enumeration { enum strict; } }\n  leaf m1 { type mode { enum loose; } }\n"),
        )])
        .is_err());
    }
}
