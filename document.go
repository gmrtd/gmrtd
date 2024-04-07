package gmrtd

type Document struct {
	CardAccess     *CardAccess
	CardSecurity   *CardSecurity // NB only read for PACE-CAM - read during PACE flow
	Dir            *EFDIR        // TODO - not fully used (or even present generally)
	Com            *COM          // TODO - BSI doc indicates this is deprecated
	Sod            *SOD          // Document Security Object EF.SOD (MANDATORY)
	Dg1            *DG1          // DATA GROUP 1 — Machine Readable Zone Information (MANDATORY)
	Dg2            *DG2          // DATA GROUP 2 — Encoded Identification Features — Face (MANDATORY)
	Dg7            *DG7          // DATA GROUP 7 — Displayed Signature or Usual Mark (OPTIONAL)
	Dg11           *DG11         // DATA GROUP 11 — Additional Personal Detail(s) (OPTIONAL)
	Dg12           *DG12         // DATA GROUP 12 — Additional Document Detail(s) (OPTIONAL)
	Dg13           *DG13         // DATA GROUP 13 — Optional Details(s) (OPTIONAL)
	Dg14           *DG14         // DATA GROUP 14 — Security Options (CONDITIONAL)
	Dg15           *DG15         // DATA GROUP 15 — Active Authentication Public Key Info (CONDITIONAL)
	Dg16           *DG16         // DATA GROUP 16 — Person(s) to Notify (OPTIONAL)
	ChipAuthStatus ChipAuthStatus
}

type ChipAuthStatus int

const (
	CHIP_AUTH_STATUS_NA ChipAuthStatus = iota
	CHIP_AUTH_STATUS_PACE_CAM
	CHIP_AUTH_STATUS_CA
	CHIP_AUTH_STATUS_AA
)
