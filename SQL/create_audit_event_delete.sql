INSERT INTO emsAudit (Scope, EventType, InitiatedBy, EventDetails)
VALUES (
    '{scope}',
    '{eventtype}',
    '{initiatedby}',
    '{field} deleted: {oldvalue}.'
);