package tui

type overlay struct {
	name    string
	isOpen  func() bool
	dismiss func()
}

// overlays is the single registration point for modal overlays, in ESC priority order: a
// new overlay adds an entry here rather than an open flag plus a dismissal branch.
func (a *App) overlays() []overlay {
	return []overlay{
		{
			name:   "status",
			isOpen: func() bool { return a.statusOpen },
			dismiss: func() {
				a.dismissStatus()
				if a.streamInFlight() {
					a.escDisarmed = true
				}
			},
		},
		{
			name:    "secretPrompt",
			isOpen:  func() bool { return a.secretPromptOpen },
			dismiss: func() { a.cancelSecretPrompt() },
		},
		{
			name:    "questionForm",
			isOpen:  func() bool { return a.questionFormOpen },
			dismiss: func() { a.cancelQuestionForm() },
		},
		{
			name:    "panel",
			isOpen:  func() bool { return a.panelOpen },
			dismiss: func() { a.dismissPanel() },
		},
		{
			name:    "effortPicker",
			isOpen:  func() bool { return a.effortPickerOpen },
			dismiss: func() { a.dismissEffortPicker() },
		},
		{
			name:    "systemOnePicker",
			isOpen:  func() bool { return a.systemOnePickerOpen },
			dismiss: func() { a.dismissSystemOnePicker() },
		},
		{
			name:    "modelPicker",
			isOpen:  func() bool { return a.modelPickerOpen },
			dismiss: func() { a.dismissModelPicker() },
		},
		{
			name:    "reverseSearch",
			isOpen:  func() bool { return a.reverseSearchOpen },
			dismiss: func() { a.dismissReverseSearch() },
		},
		{
			name:   "settingsPicker",
			isOpen: func() bool { return a.settingsPickerOpen },
			dismiss: func() {
				if a.pages.HasPage(settingsDeletePage) {
					a.cancelSettingsDelete()
					return
				}
				a.dismissSettingsPicker()
			},
		},
		{
			name:   "blockedPicker",
			isOpen: func() bool { return a.blockedPickerOpen },
			dismiss: func() {
				if a.pages.HasPage(blockedConfirmPage) {
					a.answerBlockedConfirm(false)
					return
				}
				a.dismissBlockedPicker()
			},
		},
		{
			name:    "blockedDestination",
			isOpen:  func() bool { return a.blockedDestinationOpen },
			dismiss: func() { a.answerBlockedDestination(-1) },
		},
		{
			name:    "filePicker",
			isOpen:  func() bool { return a.filePickerOpen },
			dismiss: func() { a.dismissFilePicker(true) },
		},
		{
			name:    "slashPicker",
			isOpen:  func() bool { return a.slashPickerOpen },
			dismiss: func() { a.dismissSlashPicker(true) },
		},
		{
			name:    "connectPicker",
			isOpen:  func() bool { return a.connectPickerOpen },
			dismiss: func() { a.dismissConnectPicker() },
		},
		{
			name:    "prompt",
			isOpen:  func() bool { return a.promptOpen },
			dismiss: func() { a.dismissPrompt() },
		},
		{
			// handleGlobalKey returns ESC to the focused resume list instead of calling
			// HandleEsc, so the resume picker dismisses itself with the continuation
			// result it owes its caller; it registers here for open state only.
			name:    "resumePicker",
			isOpen:  func() bool { return a.resumePickerOpen },
			dismiss: nil,
		},
	}
}
