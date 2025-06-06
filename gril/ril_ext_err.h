#define RIL_E_SUCCESS                                            0  /* Success */
#define RIL_E_RADIO_NOT_AVAILABLE                                1  /* If radio did not start or is resetting */
#define RIL_E_GENERIC_FAILURE                                    2  /* Generic Failure */
#define RIL_E_PASSWORD_INCORRECT                                 3  /* For PIN/PIN2 methods only */
#define RIL_E_SIM_PIN2                                           4  /* Operation requires SIM PIN2 to be entered */
#define RIL_E_SIM_PUK2                                           5  /* Operation requires SIM PIN2 to be entered */
#define RIL_E_REQUEST_NOT_SUPPORTED                              6  /* Not Supported request */
#define RIL_E_CANCELLED                                          7  /* Cancelled */
#define RIL_E_OP_NOT_ALLOWED_DURING_VOICE_CALL                   8  /* Data operation are not allowed during voice call on a Class C GPRS device */
#define RIL_E_OP_NOT_ALLOWED_BEFORE_REG_TO_NW                    9  /* Data operation are not allowed before device registers in network */
#define RIL_E_SMS_SEND_FAIL_RETRY                               10  /* Fail to send SMS and need retry */
#define RIL_E_SIM_ABSENT                                        11  /* Fail to set the location where CDMA subscription shall be retrieved because of SIM or RUIM are absent */
#define RIL_E_SUBSCRIPTION_NOT_AVAILABLE                        12  /* Fail to find CDMA subscription from specified location */
#define RIL_E_MODE_NOT_SUPPORTED                                13  /* Hardware does not support preferred network type */
#define RIL_E_FDN_CHECK_FAILURE                                 14  /* Command failed because recipient is not on FDN list */
#define RIL_E_ILLEGAL_SIM_OR_ME                                 15  /* Network selection failed due to illegal SIM or ME */
#define RIL_E_MISSING_RESOURCE                                  16  /* No logical channel available */
#define RIL_E_NO_SUCH_ELEMENT                                   17  /* Application not found on SIM */
#define RIL_E_DIAL_MODIFIED_TO_USSD                             18  /* DIAL request modified to USSD */
#define RIL_E_DIAL_MODIFIED_TO_SS                               19  /* DIAL request modified to SS */
#define RIL_E_DIAL_MODIFIED_TO_DIAL                             20  /* DIAL request modified to DIAL with different data */
#define RIL_E_USSD_MODIFIED_TO_DIAL                             21  /* USSD request modified to DIAL */
#define RIL_E_USSD_MODIFIED_TO_SS                               22  /* USSD request modified to SS */
#define RIL_E_USSD_MODIFIED_TO_USSD                             23  /* USSD request modified to different USSD request */
#define RIL_E_SS_MODIFIED_TO_DIAL                               24  /* SS request modified to DIAL */
#define RIL_E_SS_MODIFIED_TO_USSD                               25  /* SS request modified to USSD */
#define RIL_E_SUBSCRIPTION_NOT_SUPPORTED                        26  /* Subscription not supported */
#define RIL_E_SS_MODIFIED_TO_SS                                 27  /* SS request modified to different SS request */
#define RIL_E_LCE_NOT_SUPPORTED                                 36  /* LCE service not supported */
#define RIL_E_NO_MEMORY                                         37  /* Not sufficient memory to process the request */
#define RIL_E_INTERNAL_ERR                                      38  /* Hit unexpected vendor internal error scenario */
#define RIL_E_SYSTEM_ERR                                        39  /* Hit platform or system error */
#define RIL_E_MODEM_ERR                                         40  /* Hit unexpected modem error */
#define RIL_E_INVALID_STATE                                     41  /* Unexpected request for the current state */
#define RIL_E_NO_RESOURCES                                      42  /* Not sufficient resource to process the request */
#define RIL_E_SIM_ERR                                           43  /* Received error from SIM card */
#define RIL_E_INVALID_ARGUMENTS                                 44  /* Received invalid arguments in request */
#define RIL_E_INVALID_SIM_STATE                                 45  /* Cannot process the request in current SIM state */
#define RIL_E_INVALID_MODEM_STATE                               46  /* Cannot process the request in current Modem state */
#define RIL_E_INVALID_CALL_ID                                   47  /* Received invalid call id in request */
#define RIL_E_NO_SMS_TO_ACK                                     48  /* ACK received when there is no SMS to ack */
#define RIL_E_NETWORK_ERR                                       49  /* Received error from network */
#define RIL_E_REQUEST_RATE_LIMITED                              50  /* Operation denied due to overly-frequent requests */
#define RIL_E_SIM_BUSY                                          51  /* SIM is busy */
#define RIL_E_SIM_FULL                                          52  /* The target EF is full */
#define RIL_E_NETWORK_REJECT                                    53  /* Request is rejected by network */
#define RIL_E_OPERATION_NOT_ALLOWED                             54  /* Not allowed the request now */
#define RIL_E_EMPTY_RECORD                                      55  /* The request record is empty */
#define RIL_E_INVALID_SMS_FORMAT                                56  /* Invalid SMS format */
#define RIL_E_ENCODING_ERR                                      57  /* Message not encoded properly */
#define RIL_E_INVALID_SMSC_ADDRESS                              58  /* SMSC address specified is invalid */
#define RIL_E_NO_SUCH_ENTRY                                     59  /* No such entry present to perform the request */
#define RIL_E_NETWORK_NOT_READY                                 60  /* Network is not ready to perform the request */
#define RIL_E_NOT_PROVISIONED                                   61  /* Device does not have this value provisioned */
#define RIL_E_NO_SUBSCRIPTION                                   62  /* Device does not have subscription */
#define RIL_E_NO_NETWORK_FOUND                                  63  /* Network cannot be found */
#define RIL_E_DEVICE_IN_USE                                     64  /* Operation cannot be performed because the device is currently in use */
#define RIL_E_ABORTED                                           65  /* Operation aborted */
#define RIL_E_INCOMPATIBLE_STATE                                90  /* Operation cannot be performed because the device is in incompatible state */
#define RIL_E_NO_EFFECT                                        101  /* Given request had to no effect */
#define RIL_E_DEVICE_NOT_READY                                 102  /* Device not ready */
#define RIL_E_MISSING_ARGUMENTS                                103  /* Missing one or more arguments */
#define RIL_E_FILE_NOT_FOUND                                   104  /* Required configuration file is missing */
#define RIL_E_PIN_PERM_BLOCKED                                 201  /* PIN is permanently blocked. The SIM is unusable. */
#define RIL_E_PIN_BLOCKED                                      202  /* PIN is blocked. Unblock operation must be issued. */
#define RIL_E_MALFORMED_MSG                                   1001  /* Message was not formulated correctly by the control point or the message was corrupted during transmission */
#define RIL_E_INTERNAL                                        1003  /* Internal error */
#define RIL_E_CLIENT_IDS_EXHAUSTED                            1005  /* Client IDs exhausted */
#define RIL_E_UNABORTABLE_TRANSACTION                         1006  /* The specified transaction could not be aborted */
#define RIL_E_INVALID_CLIENT_ID                               1007  /* Could not find clients request */
#define RIL_E_NO_THRESHOLDS                                   1008  /* No thresholds specified in enable signal strength */
#define RIL_E_INVALID_HANDLE                                  1009  /* Invalid client handle was received */
#define RIL_E_INVALID_PROFILE                                 1010  /* Invalid profile index specified */
#define RIL_E_INVALID_PINID                                   1011  /* PIN in the request is invalid. */
#define RIL_E_INCORRECT_PIN                                   1012  /* PIN in the request is incorrect. */
#define RIL_E_CALL_FAILED                                     1014  /* Call origination failed in the lower layers */
#define RIL_E_OUT_OF_CALL                                     1015  /* Request issued when packet data session disconnected */
#define RIL_E_MISSING_ARG                                     1017  /* TLV was missing in the request. */
#define RIL_E_ARG_TOO_LONG                                    1019  /* Path in the request was too long. */
#define RIL_E_INVALID_TX_ID                                   1022  /* The transaction ID supplied in the request does not match any pending transaction i.e. either the transaction was not received or it is already executed by the device */
#define RIL_E_OP_NETWORK_UNSUPPORTED                          1024  /* Selected operation is not supported by the network */
#define RIL_E_OP_DEVICE_UNSUPPORTED                           1025  /* Operation is not supported by device or SIM card */
#define RIL_E_NO_FREE_PROFILE                                 1027  /* Maximum number of profiles are stored in the device and there is no more storage available to create a new profile */
#define RIL_E_INVALID_PDP_TYPE                                1028  /* PDP type specified is not supported */
#define RIL_E_INVALID_TECH_PREF                               1029  /* Invalid technology preference */
#define RIL_E_INVALID_PROFILE_TYPE                            1030  /* Invalid profile type is specified */
#define RIL_E_INVALID_SERVICE_TYPE                            1031  /* Invalid service type */
#define RIL_E_INVALID_REGISTER_ACTION                         1032  /* Invalid register action value specified in request */
#define RIL_E_INVALID_PS_ATTACH_ACTION                        1033  /* Invalid PS attach action value specified in request */
#define RIL_E_AUTHENTICATION_FAILED                           1034  /* Authentication error. */
#define RIL_E_SIM_NOT_INITIALIZED                             1037  /* PIN is not yet initialized because the SIM initialization has not finished. Try the PIN operation later. */
#define RIL_E_MAX_QOS_REQUESTS_IN_USE                         1038  /* Maximum QoS requests in use */
#define RIL_E_INCORRECT_FLOW_FILTER                           1039  /* Incorrect flow filter */
#define RIL_E_NETWORK_QOS_UNAWARE                             1040  /* Network QoS unaware */
#define RIL_E_INVALID_ID                                      1041  /* Invalid call ID was sent in the request */
#define RIL_E_REQUESTED_NUM_UNSUPPORTED                       1042  /* Requested message ID is not supported by the currently running software */
#define RIL_E_INTERFACE_NOT_FOUND                             1043  /* Cannot retrieve the FMC interface */
#define RIL_E_FLOW_SUSPENDED                                  1044  /* Flow suspended */
#define RIL_E_INVALID_DATA_FORMAT                             1045  /* Invalid data format */
#define RIL_E_GENERAL                                         1046  /* General error */
#define RIL_E_UNKNOWN                                         1047  /* Unknown error */
#define RIL_E_INVALID_ARG                                     1048  /* Parameters passed as input were invalid */
#define RIL_E_INVALID_INDEX                                   1049  /* MIP profile index is not within the valid range */
#define RIL_E_NO_ENTRY                                        1050  /* No message exists at the specified memory storage designation */
#define RIL_E_DEVICE_STORAGE_FULL                             1051  /* Memory storage specified in the request is full */
#define RIL_E_CAUSE_CODE                                      1054  /* There was an error in the request */
#define RIL_E_MESSAGE_NOT_SENT                                1055  /* Message could not be sent */
#define RIL_E_MESSAGE_DELIVERY_FAILURE                        1056  /* Message could not be delivered */
#define RIL_E_INVALID_MESSAGE_ID                              1057  /* Message ID specified for the message is invalid */
#define RIL_E_ENCODING                                        1058  /* Message is not encoded properly */
#define RIL_E_AUTHENTICATION_LOCK                             1059  /* Maximum number of authentication failures has been reached */
#define RIL_E_INVALID_TRANSITION                              1060  /* Selected operating mode transition from the current operating mode is invalid */
#define RIL_E_NOT_A_MCAST_IFACE                               1061  /* Not a MCAST interface */
#define RIL_E_MAX_MCAST_REQUESTS_IN_USE                       1062  /* MCAST request in use */
#define RIL_E_INVALID_MCAST_HANDLE                            1063  /* An invalid MCAST handle */
#define RIL_E_INVALID_IP_FAMILY_PREF                          1064  /* IP family preference is invalid */
#define RIL_E_SESSION_INACTIVE                                1065  /* Session inactive */
#define RIL_E_SESSION_INVALID                                 1066  /* Session not valid */
#define RIL_E_SESSION_OWNERSHIP                               1067  /* Session ownership error */
#define RIL_E_INSUFFICIENT_RESOURCES                          1068  /* Response is longer than the maximum supported size */
#define RIL_E_DISABLED                                        1069  /* Disabled */
#define RIL_E_INVALID_OPERATION                               1070  /* Device is not expecting the request. */
#define RIL_E_INVALID_QMI_CMD                                 1071  /* Invalid QMI command */
#define RIL_E_TPDU_TYPE                                       1072  /* Message in memory contains a TPDU type that cannot be read */
#define RIL_E_SMSC_ADDR                                       1073  /* SMSC address specified is invalid */
#define RIL_E_INFO_UNAVAILABLE                                1074  /* Information is not available */
#define RIL_E_SEGMENT_TOO_LONG                                1075  /* PRL segment size is too large */
#define RIL_E_SEGMENT_ORDER                                   1076  /* PRL segment order is incorrect */
#define RIL_E_BUNDLING_NOT_SUPPORTED                          1077  /* Bundling not supported */
#define RIL_E_OP_PARTIAL_FAILURE                              1078  /* Some personalization codes were set but an error prevented */
#define RIL_E_POLICY_MISMATCH                                 1079  /* Network policy does not match a valid NAT */
#define RIL_E_SIM_FILE_NOT_FOUND                              1080  /* File is not present on the card. */
#define RIL_E_EXTENDED_INTERNAL                               1081  /* Error from the the DS profile module, the extended error */
#define RIL_E_ACCESS_DENIED                                   1082  /* Access to the requested file is denied. This can occur when there is an attempt to access a PIN-protected file. */
#define RIL_E_HARDWARE_RESTRICTED                             1083  /* Selected operating mode is invalid with the current wireless disable setting */
#define RIL_E_ACK_NOT_SENT                                    1084  /* ACK could not be sent */
#define RIL_E_INJECT_TIMEOUT                                  1085  /* Inject timeout */
#define RIL_E_FDN_RESTRICT                                    1091  /* FDN restriction */
#define RIL_E_SUPS_FAILURE_CAUSE                              1092  /* Indicates supplementary services failure information; */
#define RIL_E_NO_RADIO                                        1093  /* Radio is not available */
#define RIL_E_NOT_SUPPORTED                                   1094  /* Operation is not supported */
#define RIL_E_CARD_CALL_CONTROL_FAILED                        1096  /* SIM/R-UIM call control failed */
#define RIL_E_NETWORK_ABORTED                                 1097  /* Operation was released abruptly by the network */
#define RIL_E_MSG_BLOCKED                                     1098  /* Message blocked */
#define RIL_E_INVALID_SESSION_TYPE                            1100  /* Invalid session type */
#define RIL_E_INVALID_PB_TYPE                                 1101  /* Invalid Phone Book type */
#define RIL_E_NO_SIM                                          1102  /* Action is being performed on a SIM that is not initialized. */
#define RIL_E_PB_NOT_READY                                    1103  /* Phone Book not ready */
#define RIL_E_PIN_RESTRICTION                                 1104  /* PIN restriction */
#define RIL_E_PIN2_RESTRICTION                                1105  /* PIN2 restriction */
#define RIL_E_PUK_RESTRICTION                                 1106  /* PUK restriction */
#define RIL_E_PUK2_RESTRICTION                                1107  /* PUK2 restriction */
#define RIL_E_PB_ACCESS_RESTRICTED                            1108  /* Phone Book access restricted */
#define RIL_E_PB_DELETE_IN_PROG                               1109  /* Phone Book delete in progress */
#define RIL_E_PB_TEXT_TOO_LONG                                1110  /* Phone Book text too long */
#define RIL_E_PB_NUMBER_TOO_LONG                              1111  /* Phone Book number too long */
#define RIL_E_PB_HIDDEN_KEY_RESTRICTION                       1112  /* Phone Book hidden key restriction */
#define RIL_E_PB_NOT_AVAILABLE                                1113  /* Phone Book not available */
#define RIL_E_DEVICE_MEMORY_ERROR                             1114  /* Device memory error */
#define RIL_E_NO_PERMISSION                                   1115  /* No permission */
#define RIL_E_TOO_SOON                                        1116  /* Too soon */
#define RIL_E_TIME_NOT_ACQUIRED                               1117  /* Time not acquired */
#define RIL_E_OP_IN_PROGRESS                                  1118  /* Operation is in progress */
#define RIL_E_DS_PROFILE_REG_RESULT_FAIL                      2001  /* General failure */
#define RIL_E_DS_PROFILE_REG_RESULT_ERR_INVAL_HNDL            2002  /* Request contains an invalid profile handle */
#define RIL_E_DS_PROFILE_REG_RESULT_ERR_INVAL_OP              2003  /* Invalid operation was requested */
#define RIL_E_DS_PROFILE_REG_RESULT_ERR_INVAL_PROFILE_TYPE    2004  /* Request contains an invalid technology type */
#define RIL_E_DS_PROFILE_REG_RESULT_ERR_INVAL_PROFILE_NUM     2005  /* Request contains an invalid profile number */
#define RIL_E_DS_PROFILE_REG_RESULT_ERR_INVAL_IDENT           2006  /* Request contains an invalid profile identifier */
#define RIL_E_DS_PROFILE_REG_RESULT_ERR_INVAL                 2007  /* Request contains an invalid argument other than profile number and profile identifier received */
#define RIL_E_DS_PROFILE_REG_RESULT_ERR_LIB_NOT_INITED        2008  /* Profile registry has not been initialized yet */
#define RIL_E_DS_PROFILE_REG_RESULT_ERR_LEN_INVALID           2009  /* Request contains a parameter with invalid length */
#define RIL_E_DS_PROFILE_REG_RESULT_LIST_END                  2010  /* End of the profile list was reached while searching for the requested profile */
#define RIL_E_DS_PROFILE_REG_RESULT_ERR_INVAL_SUBS_ID         2011  /* Request contains an invalid subscription identifier */
#define RIL_E_DS_PROFILE_REG_INVAL_PROFILE_FAMILY             2012  /* Request contains an invalid profile family */
#define RIL_E_DS_PROFILE_REG_PROFILE_VERSION_MISMATCH         2013  /* Version mismatch */
#define RIL_E_REG_RESULT_ERR_OUT_OF_MEMORY                    2014  /* Out of memory */
#define RIL_E_DS_PROFILE_REG_RESULT_ERR_FILE_ACCESS           2015  /* File access error */
#define RIL_E_DS_PROFILE_REG_RESULT_ERR_EOF                   2016  /* End of field */
#define RIL_E_REG_RESULT_ERR_VALID_FLAG_NOT_SET               2017  /* A valid flag is not set */
#define RIL_E_REG_RESULT_ERR_OUT_OF_PROFILES                  2018  /* Out of profiles */
#define RIL_E_REG_RESULT_NO_EMERGENCY_PDN_SUPPORT             2019  /* No emergency PDN support */
#define RIL_E_V2X_ERR_EXCEED_MAX                              3000  /* Exceed max allowed number */
#define RIL_E_V2X_ERR_V2X_DISABLED                            3001  /* V2x mode was not enabled */
#define RIL_E_V2X_ERR_UNKNOWN_SERVICE_ID                      3002  /* The service id unknown */
#define RIL_E_V2X_ERR_SRV_ID_L2_ADDRS_NOT_COMPATIBLE          3003  /* The service Id mismatch with L2 addr */
#define RIL_E_V2X_ERR_PORT_UNAVAIL                            3004  /* The port was occupied by others */
#define RIL_E_DS_PROFILE_3GPP_INVAL_PROFILE_FAMILY            4097  /* Request contains an invalid 3GPP profile family */
#define RIL_E_DS_PROFILE_3GPP_ACCESS_ERR                      4098  /* Error was encountered while accessing the 3GPP profiles */
#define RIL_E_DS_PROFILE_3GPP_CONTEXT_NOT_DEFINED             4099  /* Specified 3GPP profile does not have a valid context */
#define RIL_E_DS_PROFILE_3GPP_VALID_FLAG_NOT_SET              4100  /* Specified 3GPP profile is marked invalid */
#define RIL_E_DS_PROFILE_3GPP_READ_ONLY_FLAG_SET              4101  /* Specified 3GPP profile is marked read-only */
#define RIL_E_DS_PROFILE_3GPP_ERR_OUT_OF_PROFILES             4102  /* Creation of a new 3GPP profile failed because the limit of 16 profiles has already been reached */
#define RIL_E_DS_PROFILE_3GPP2_ERR_INVALID_IDENT_FOR_PROFILE  4353  /* Invalid profile identifier was received as part of the 3GPP2 profile modification request */
#define RIL_E_DS_PROFILE_3GPP2_ERR_OUT_OF_PROFILE             4354  /* Creation of a new 3GPP2 profile failed because the limit has already been reached */
#define RIL_E_INTERNAL_ERROR                                    -1  /* Internal error */
#define RIL_E_SERVICE_ERROR                                     -2  /* Service error */
#define RIL_E_TIMEOUT_ERROR                                     -3  /* Timeout error */
#define RIL_E_EXTENDED_ERROR                                    -4  /* Extended error */
#define RIL_E_PORT_NOT_OPEN_ERROR                               -5  /* Port not open */
#define RIL_E_MEMCOPY_ERROR                                    -13  /* Memory copy error */
#define RIL_E_INVALID_TRANSACTION                              -14  /* Invalid transaction */
#define RIL_E_ALLOCATION_FAILURE                               -15  /* Allocation failure */
#define RIL_E_TRANSPORT_ERROR                                  -16  /* Transport error */
#define RIL_E_PARAM_ERROR                                      -17  /* Parameter error */
#define RIL_E_INVALID_CLIENT                                   -18  /* Invalid client */
#define RIL_E_FRAMEWORK_NOT_READY                              -19  /* Framework not ready */
#define RIL_E_INVALID_SIGNAL                                   -20  /* Invalid signal */
#define RIL_E_TRANSPORT_BUSY_ERROR                             -21  /* Transport busy error */
#define RIL_E_SUBSYSTEM_UNAVAILABLE                           5000  /* Underlying service currently unavailable */
#define RIL_E_OPERATION_TIMEOUT                               5001  /* Timeout error */
#define RIL_E_ROLLBACK_FAILED                                 5002  /* Rollback to initial state failed */
#define RIL_E_ROT_ALREADY_SET                                 5003  /* Root of trust already configured */
#define RIL_E_UNSUPPORTED_PURPOSE                             5004  /* Unsupported use of the key */
#define RIL_E_INCOMPATIBLE_PURPOSE                            5005  /* Incompatible purpose */
#define RIL_E_UNSUPPORTED_ALGO                                5006  /* Unsupported algorithm */
#define RIL_E_INCOMPATIBLE_ALGO                               5007  /* Incompatible algorithm */
#define RIL_E_UNSUPPORTED_KEY_SIZE                            5008  /* Unsupported key size */
#define RIL_E_UNSUPPORTED_BLOCK_MODE                          5009  /* Unsupported block mode */
#define RIL_E_INCOMPATIBLE_BLOCK_MODE                         5010  /* Incompatible block mode */
#define RIL_E_UNSUPPORTED_MAC_LEN                             5011  /* Unsupported MAC length */
#define RIL_E_UNSUPPORTED_PADDING_MODE                        5012  /* Unsupported padding mode */
#define RIL_E_UNSUPPORTED_DIGEST                              5013  /* Unsupported digest */
#define RIL_E_INCOMPATIBLE_DIGEST                             5014  /* Incompatible digest */
#define RIL_E_INVAL_EXP_TIME                                  5015  /* Invalid expiration time */
#define RIL_E_INVAL_USR_ID                                    5016  /* Invalid user ID */
#define RIL_E_INVAL_AUTH_TIMEOUT                              5017  /* Invalid authorization timeout */
#define RIL_E_UNSUPPORTED_KEY_FMT                             5018  /* Unsupported key format */
#define RIL_E_INCOMPATIBLE_KEY_FMT                            5019  /* Incompatible key format */
#define RIL_E_UNSUPPORTED_KEY_ENC_ALGO                        5020  /* Unsupported key encryption algorithm (for PKCS8 & PKCS12) */
#define RIL_E_UNSUPPORTED_KEY_VRFY_ALGO                       5021  /* Unsupported key verification algorithm (for PKCS8 & PKCS12) */
#define RIL_E_INVAL_IN_LEN                                    5022  /* Invalid input length */
#define RIL_E_INVAL_KEY_EXPRT_OPTNS                           5023  /* Invalid oprions for key export */
#define RIL_E_DELEGATION_NOT_ALLOWED                          5024  /* Delegation not allowed */
#define RIL_E_KEY_NOT_YET_VALID                               5025  /* Key still not valid */
#define RIL_E_KEY_EXPIRED                                     5026  /* Key has expired */
#define RIL_E_KEY_USR_NOT_AUTHENTICATED                       5027  /* Key user not authenticated */
#define RIL_E_OUT_PARAMETER_NULL                              5028  /* Null output argument */
#define RIL_E_INVAL_OPERATION_HNDL                            5029  /* Invalid operation handle */
#define RIL_E_INSUFFICIENT_BUF_SPACE                          5030  /* Insufficient buffer space */
#define RIL_E_VERIFICATION_FAILED                             5031  /* Verifcation failed */
#define RIL_E_TOO_MANY_OPS                                    5032  /* Too many operations */
#define RIL_E_UNEXPECTED_NULL_PTR                             5033  /* Unexpected null pointer */
#define RIL_E_INVAL_KEY_BLOB                                  5034  /* Invalid key blob */
#define RIL_E_IMPORTED_KEY_NOT_ENC                            5035  /* Imported key not encrypted */
#define RIL_E_IMPORTED_KEY_DEC_FAIL                           5036  /* Imported key decryption failed */
#define RIL_E_IMPORTED_KEY_NOT_SIGNED                         5037  /* Imported key not signed */
#define RIL_E_IMPORTED_KEY_VRFY_FAIL                          5038  /* Imported key verification failed */
#define RIL_E_UNSUPPORTED_TAG                                 5039  /* Unsupported tag */
#define RIL_E_INVAL_TAG                                       5040  /* Invalid TAG */
#define RIL_E_IMPORT_PARAM_MISMATCH                           5041  /* Mismatch in import parameters */
#define RIL_E_SEC_HW_ACCESS_DENIED                            5042  /* Secure hardware access denied */
#define RIL_E_CONCUR_ACCESS_CONFLICT                          5043  /* Concurrent access conflict */
#define RIL_E_SEC_HW_BUSY                                     5044  /* Secure hardware busy */
#define RIL_E_SEC_HW_COM_FAIL                                 5045  /* Secure hardware communication failed */
#define RIL_E_UNSUPPORTED_EC_FIELD                            5046  /* Unsupported EC field */
#define RIL_E_MISSING_NONCE                                   5047  /* Missing nonce */
#define RIL_E_INVAL_NONCE                                     5048  /* Invalid nonce */
#define RIL_E_MISSING_MAC_LEN                                 5049  /* Missing MAC length */
#define RIL_E_KEY_RATE_LIMIT_EXCEEDED                         5050  /* Key limit exceeded */
#define RIL_E_CALLER_NONCE_PROHIBITED                         5051  /* Caller nonce proibited */
#define RIL_E_KEY_MAX_OPS_EXCEEDED                            5052  /* Key maximum operations exceeded */
#define RIL_E_INVAL_MAC_LEN                                   5053  /* Invalid MAC length */
#define RIL_E_MISSING_MIN_MAC_LEN                             5054  /* Missing minimum MAC length */
#define RIL_E_UNSUPPORTED_MIN_MAC_LEN                         5055  /* Unsupported minimum MAC length */
#define RIL_E_UNSUPPORTED_KDF                                 5056  /* Unsupported KDF */
#define RIL_E_UNSUPPORTED_EC_CURVE                            5057  /* Unsupported EC curve */
#define RIL_E_KEY_REQ_UPGRADE                                 5058  /* Key requires upgrade */
#define RIL_E_ATTESTATION_CHLNG_MIS                           5059  /* Attestation challenge missing */
#define RIL_E_KM_NOT_CONFGRD                                  5060  /* Keymaster not configured */
#define RIL_E_ATTESTATION_APPID_MIS                           5061  /* Attestation app ID missing */
#define RIL_E_CANNOT_ATTEST_IDS                               5062  /* Can not attest IDs */
#define RIL_E_UNIMPLEMENTED                                   5063  /* Unimplemented */
#define RIL_E_VER_MISMATCH                                    5064  /* Version mismatch */
#define RIL_E_SOTER_ERR                                       5065  /* Soter error */
#define RIL_E_DMA_ERR                                         5066  /* HSDMA error */
#define RIL_E_DIV_ERR                                         5067  /* Divided by error */
#define RIL_E_OVERFLOW_UNDERFLOW                              5068  /* Arithmetic overflow or underflow */
#define RIL_E_RNG_UNSEEDED                                    5069  /* Read from unseeded ring */
#define RIL_E_MEM_ERR                                         5070  /* Memory read */
#define RIL_E_MODULUS_ERR                                     5071  /* Modulus error */
#define RIL_E_DECODING_ERR                                    5072  /* Decode error */
#define RIL_E_INVALID_LENGTH                                  5073  /* Invalid length of data */
