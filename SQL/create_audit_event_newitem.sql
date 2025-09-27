INSERT INTO emsAudit (Scope, EventType, InitiatedBy, EventDetails)
VALUES (
    '{scope}',
    '{eventtype}',
    '{initiatedby}',
    'New {field} created: {newvalue}.'
);