//! Fixed read-only physical-schema observation for restart classification.

use rusqlite::Connection;

use crate::database_schema_v2_contract::{
    ObservedColumn, ObservedForeignKey, ObservedIndex, ObservedTable, ObservedUniqueConstraint,
    ObservedV2Schema, V2_INDEXES, V2_SCHEMA_DDL, V2_TABLES,
};

const SCHEMA_OBJECTS_QUERY: &str = "SELECT type, name, tbl_name, sql
FROM main.sqlite_schema
WHERE name NOT LIKE 'sqlite_%'
ORDER BY type, name";

pub(super) fn observe_restart_schema(
    connection: &Connection,
    user_version: u32,
    metadata_contract_version: u16,
    metadata_database_schema_version: u16,
) -> Result<ObservedV2Schema, ()> {
    let mut statement = connection.prepare(SCHEMA_OBJECTS_QUERY).map_err(|_| ())?;
    let mut rows = statement.query([]).map_err(|_| ())?;
    let mut business_tables = Vec::new();
    let mut business_indexes = Vec::new();
    let mut invalid_objects = Vec::new();

    while let Some(row) = rows.next().map_err(|_| ())? {
        let kind = row.get::<_, String>(0).map_err(|_| ())?;
        let name = row.get::<_, String>(1).map_err(|_| ())?;
        let table = row.get::<_, String>(2).map_err(|_| ())?;
        let sql = row.get::<_, Option<String>>(3).map_err(|_| ())?;

        if kind == "table" && name == "church_app_database_metadata" && table == name {
            continue;
        }
        if let Some((offset, contract)) = V2_TABLES
            .iter()
            .enumerate()
            .find(|(_, contract)| contract.name == name)
        {
            if kind == "table" && table == name && sql.as_deref() == Some(V2_SCHEMA_DDL[offset]) {
                business_tables.push(observed_table(contract));
            } else {
                business_tables.push(invalid_table(name));
            }
            continue;
        }
        if let Some((offset, contract)) = V2_INDEXES
            .iter()
            .enumerate()
            .find(|(_, contract)| contract.name == name)
        {
            if kind == "index"
                && table == contract.table
                && sql.as_deref() == Some(V2_SCHEMA_DDL[V2_TABLES.len() + offset])
            {
                business_indexes.push(ObservedIndex {
                    name: contract.name.to_owned(),
                    table: contract.table.to_owned(),
                    columns: contract
                        .columns
                        .iter()
                        .map(|column| (*column).to_owned())
                        .collect(),
                    unique: contract.unique,
                    predicate: contract.predicate,
                });
            } else {
                business_indexes.push(ObservedIndex {
                    name,
                    table,
                    columns: Vec::new(),
                    unique: false,
                    predicate: None,
                });
            }
            continue;
        }
        invalid_objects.push(name);
    }

    Ok(ObservedV2Schema {
        user_version,
        metadata_contract_version,
        metadata_database_schema_version,
        business_tables,
        business_indexes,
        triggers: invalid_objects,
    })
}

fn observed_table(contract: &crate::database_schema_v2_contract::TableContract) -> ObservedTable {
    ObservedTable {
        name: contract.name.to_owned(),
        columns: contract
            .columns
            .iter()
            .map(|column| ObservedColumn {
                name: column.name.to_owned(),
                sqlite_type: column.sqlite_type,
                nullable: column.nullable,
                primary_key_ordinal: column.primary_key_ordinal,
                has_default: column.has_default,
            })
            .collect(),
        checks: contract.checks.to_vec(),
        foreign_keys: contract
            .foreign_keys
            .iter()
            .map(|foreign_key| ObservedForeignKey {
                columns: foreign_key
                    .columns
                    .iter()
                    .map(|column| (*column).to_owned())
                    .collect(),
                referenced_table: foreign_key.referenced_table.to_owned(),
                referenced_columns: foreign_key
                    .referenced_columns
                    .iter()
                    .map(|column| (*column).to_owned())
                    .collect(),
                on_update: foreign_key.on_update,
                on_delete: foreign_key.on_delete,
            })
            .collect(),
        unique_constraints: contract
            .unique_constraints
            .iter()
            .map(|unique| ObservedUniqueConstraint {
                columns: unique
                    .columns
                    .iter()
                    .map(|column| (*column).to_owned())
                    .collect(),
            })
            .collect(),
        strict: contract.strict,
        without_rowid: contract.without_rowid,
    }
}

fn invalid_table(name: String) -> ObservedTable {
    ObservedTable {
        name,
        columns: Vec::new(),
        checks: Vec::new(),
        foreign_keys: Vec::new(),
        unique_constraints: Vec::new(),
        strict: false,
        without_rowid: false,
    }
}
