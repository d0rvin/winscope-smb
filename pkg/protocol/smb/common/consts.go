package common

const (
	StatusOk                     = 0x00000000
	StatusMoreProcessingRequired = 0xc0000016
	StatusInvalidParameter       = 0xc000000d
	StatusLogonFailure           = 0xc000006d
	StatusUserSessionDeleted     = 0xc0000203
)

var StatusMap = map[uint32]string{
	StatusOk:                     "OK",
	StatusMoreProcessingRequired: "More Processing Required",
	StatusInvalidParameter:       "Invalid Parameter",
	StatusLogonFailure:           "Logon failed",
	StatusUserSessionDeleted:     "User session deleted",
}
