from sigma.pipelines.common import logsource_windows, windows_logsource_mapping
from sigma.processing.transformations import AddConditionTransformation, FieldMappingTransformation, DetectionItemFailureTransformation, RuleFailureTransformation, SetStateTransformation
from sigma.processing.conditions import LogsourceCondition, IncludeFieldCondition, ExcludeFieldCondition, RuleProcessingItemAppliedCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline

def ossem_to_sigma() -> ProcessingPipeline:      # Processing pipelines should be defined as functions that return a ProcessingPipeline object.
    return ProcessingPipeline(
        name="OSSEM pipeline",
        priority=20,            # The priority defines the order pipelines are applied. See documentation for common values.
        items=[
            ProcessingItem(     # Field mappings
                identifier="ossem_field_mapping",
                transformation=FieldMappingTransformation({
                    # Process Entity 
                    #### / process_creation
                    "ProcessCommandLine": "CommandLine",
                    "ProcessFilePath": "Image",
                    "ProcessIntegrityLevel":"IntegrityLevel",
                    "ProcessFileProduct":"Product",
                    "ProcessFileDescription":"Description",
                    "ProcessFileCompany":"Company",
                    "ProcessFileDirectory":"CurrentDirectory",
                    "ProcessHashSha1":"sha1",
                    "ProcessHashImphash":"Imphash",
                    "ProcessHashImphash":"Hashes", # check https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_bypass_squiblytwo.yml
                    "":"OriginalFileName", #----> Field is not part of Process Entity, check Sysmon 1
                    #### / process_access
                    "ProcessCallTrace":"CallTrace",
                    "ProcessGrantedAccess":"GrantedAccess",
                    "ProcessFilePath":"SourceImage", # Image and SourceImage would have the same OSSEM mapping
                    "TargetProcessFilePath":"TargetImage",
                    #### Process Entity (ProcessParent) / process_creation
                    "ProcessParentCommandLine": "ParentCommandLine",
                    "ProcessParentFilePath": "ParentImage",
                    "ProcessParentIntegrityLevel":"",
                    "ProcessParentProduct":"",
                    "ProcessParentFileDescription":"",
                    "ProcessParentFileCompany":"",
                    "ProcessParentFileDirectory":"",
                    "ProcessParentHashSha1":"",
                    "ProcessParentHashImphash":"",
                    #### Process Entity (ProcessParent) / process_access
                    "ProcessParentCallTrace": "",
                    "ProcessParentGrantedAccess": "",
                    # User Entity
                    "UserName":"User",
                    # Computer (Device from OSSEM??)
                    "":"ComputerName", # example event 4776, uses Hostname. Device entity has Hostname field.
                    # Logon Entity
                    "LogonGuid":"LogonGuid",
                    # Registry Entity
                    "RegistryValueData":"Details", # I need to validate if Details comes from registry events https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_cmstp_execution_by_creation.yml
                    # Not Entity related fields
                    "":"Provider_Name" # Currently, we only map fields from event_data no from the system_data https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_access/proc_access_win_direct_syscall_ntopenprocess.yml
                })
            )
        ],
    )