"""Used to record constants declarations. Please use it only for variables that might change their values over time"""

__copyright__ = "Copyright 2020 NXP"

# Synchronization constants. Used by sync_workers_utils
SYNC_WORKERS_SQLITE_FILE = r'_PROCESSOR_\Builds\locks\sync_workers.db'

# Database lock file used to manage concurrent access to a resource
LOCK_RESOURCE_SQLITE_FILE = r'_PROCESSOR_\Builds\locks\lock_resource.db'

AUTOMATION_SCRIPTS_URL = "_BITBUCKET_/projects/AMPAT/repos/automation_scripts"


class DatabaseConstants(object):
    """Generic constants for database operations"""

    LOCK_WAIT_TIME = 5
    TABLE_FIELDS = {'resource_id_field': 'Resource_Id', 'lock_status_field': 'Lock_Status'}

    class SqlCommands(object):
        """Database operation commands"""

        UPDATE = (
            'UPDATE {table_name} SET {lock_status_field} = {lock_status} WHERE {resource_id_field} = "{resource_id}";'
        )

        IS_LOCKED = 'SELECT {lock_status_field} FROM {table_name} WHERE {resource_id_field} = "{resource_id}";'

    COMMANDS = SqlCommands()


class CoverityConstants(object):
    """Constants used by Coverity tools and automation framework"""

    COVERITY_SQLITE_FILE = r'_PROCESSOR_\Builds\locks\coverity_resource.db'
    COVERITY_TABLE_NAME = 'Coverity_Resource'
    TABLE_FIELDS = {'entry_id_field': 'ID',
                    'resource_id_field': 'Bamboo_Build_Key',
                    'resource_type_field': 'Resource_Type',
                    'lock_status_field': 'Lock_Status',
                    'execution_status_field': 'Execution_Status'}
    COVERITY_RESPONSE_INDEX = 0
    COVERITY_ID_INDEX = 0
    COVERITY_LOCK_STATUS_INDEX = 1
    COVERITY_EXECUTION_STATUS_INDEX = 2
    COVERITY_ACQUIRE_TIMEOUT = 120
    COVERITY_WAIT_FOR_ACQUIRE_INTERVAL = 5
    COVERITY_SYNC_TIMEOUT = 600
    COVERITY_WAIT_FOR_SYNC_INTERVAL = 30
    COVERITY_EXECUTION_TIMEOUT = 60
    COVERITY_WAIT_FOR_EXECUTION_INTERVAL = 10
    COVERITY_CREATE_STREAM_TIMEOUT = 100
    COVERITY_EXECUTION_NOT_STARTED = 'NOT EXECUTED'
    COVERITY_EXECUTION_OK = 'OK'
    COVERITY_EXECUTION_FAIL = 'FAIL'
    COVERITY_EXECUTION_IN_PROGRESS = 'IN PROGRESS'
    COVERITY_GET_STREAMS_HEADER = 'Stream,Language,Description,Primary Project,Triage Store,Expiration'
    COVERITY_GET_TRIAGE_STORES_HEADER = 'Triage Store,Description'
    COVERITY_STATIC_ANALYSIS_CHECKERS = ["misra", "his"]
    COVERITY_REPORT_ABOUT_WORKSHEET, COVERITY_REPORT_CONFIGURATION_WORKSHEET, COVERITY_REPORT_ANALYSIS_WORKSHEET = (
        "About", "Configuration", "Analysis"
    )
    COVERITY_REPORT_CID_INDEX = 1

    class CoverityDashOptions(object):
        """Definitions for keys used by cov-analyze and specified in coverity configuration"""

        SINGLE_DASH_OPT = 'single-dash-opts'
        DOUBLE_DASH_OPT = 'double-dash-opts'

    class CoverityXMLViolations(object):
        """The structure of an xml violation"""

        XML_VIOLATION_STRUCTURE = {
            "domain": str,
            "lang": str,
            "checker": str,
            "type": str,
            "file": str,
            "merge_with_lowercase_file": str,
            "function": str,
            "score": str,
            "ordered": str,
            "event": dict(
                {
                    "main": str,
                    "tag": str,
                    "description": str,
                    "line": str
                }
            ),
            "extra": str,
            "subcategory": str,
            "antecedentMerge": dict(
                {
                    "domain": str,
                    "checker": str,
                    "file": str,
                    "function": str,
                    "extra": dict
                }
            )
        }

    class CoveritySqlCommands(object):
        """Coverity specific database commands"""

        INSERT = (
            'INSERT INTO {table_name} ({resource_id_field}, {resource_type_field}, {lock_status_field}, '
            '{execution_status_field}) VALUES ("{build_key}", "{resource_type}", {lock_status}, '
            '{execution_status!r});'
        )

        UPDATE_LOCK_STATUS = (
            'UPDATE {table_name} SET {lock_status_field} = {lock_status} WHERE '
            '{resource_id_field} = "{resource_id}" AND {resource_type_field} = "{resource_type}";'
        )

        UPDATE_EXECUTION_STATUS = (
            'UPDATE {table_name} SET {execution_status_field} = {execution_status!r} WHERE '
            '{resource_id_field} = "{resource_id}" AND {resource_type_field} = "{resource_type}";'
        )

        GET_ENTRY_STATUS = (
            'SELECT {entry_id_field}, {lock_status_field}, {execution_status_field} '
            'FROM {table_name} WHERE '
            '{resource_id_field} = "{resource_id}" AND {resource_type_field} = "{resource_type}";'
        )

    COMMANDS = CoveritySqlCommands()

    COVERITY_COORDINATOR = 'coverity.nxp.com'
