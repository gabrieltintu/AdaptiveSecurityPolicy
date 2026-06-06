package com.adaptivesecurity.api.entity.enums;

/** Type of action recorded in the audit log. */
public enum AuditAction {
    BLOCK,
    UNBLOCK,
    WARN,
    KNOCK,
    CONFIG_CHANGE,
    WHITELIST_ADD,
    WHITELIST_REMOVE
}
