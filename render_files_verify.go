package main

import (
	"os"
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/aixoio/aixoio-privacy-tools/lib/rsahelper"
)

func render_files_verify(w fyne.Window) fyne.CanvasObject {
	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_files(w)) })
	path := ""
	path_wid := widget.NewLabel(path)
	path_key := ""
	path_wid_key := widget.NewLabel(path_key)
	path_sig := ""
	path_wid_sig := widget.NewLabel(path_sig)
	opts := []string{"PGP", "RSA"}
	sel_wid := widget.NewSelect(opts, func(s string) {})
	sel_wid.SetSelectedIndex(0)

	actbtn := widget.NewButton("Verify", func() {
		file_dat, err := os.ReadFile(path)
		if err != nil {
			show_err(w)
			return
		}

		pk_key, err := os.ReadFile(path_key)
		if err != nil {
			show_err(w)
			return
		}

		sig_file, err := os.ReadFile(path_sig)
		if err != nil {
			show_err(w)
			return
		}

		switch sel_wid.SelectedIndex() {
		case 0: // PGP
			var wg sync.WaitGroup

			wg.Add(1)

			go func() {
				defer wg.Done()
				var ring *crypto.Key
				ring, err = crypto.NewKeyFromArmoredReader(strings.NewReader(string(pk_key)))
				var key_ring_sign *crypto.KeyRing
				key_ring_sign, err = crypto.NewKeyRing(ring)
				var sig *crypto.PGPSignature
				sig, err = crypto.NewPGPSignatureFromArmored(string(sig_file))
				err = key_ring_sign.VerifyDetached(crypto.NewPlainMessage(file_dat), sig, crypto.GetUnixTime())
			}()

			d := dialog.NewCustomWithoutButtons("Verifying - "+path_wid.Text, container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()

			wg.Wait()

			d.Hide()

			if err != nil {
				dialog.ShowInformation("Infomation", "The file is NOT verifyed and NOT signed by the public key you selected", w)
				return
			} else {
				dialog.ShowInformation("Infomation", "The file is verifyed and signed by the public key you selected", w)
			}

		case 1: // RSA
			var wg sync.WaitGroup

			wg.Add(1)

			var good bool

			go func() {
				defer wg.Done()
				key, gerr := rsahelper.ExportPEMStrToPubKey(pk_key)
				if gerr != nil {
					err = gerr
					return
				}
				good = rsahelper.RsaVerify(key, sig_file, file_dat)
			}()

			d := dialog.NewCustomWithoutButtons("Verifying - "+path_wid.Text, container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()

			wg.Wait()

			d.Hide()

			if err != nil {
				show_err(w)
				return
			}

			if !good {
				dialog.ShowInformation("Infomation", "The file is NOT verifyed and NOT signed by the public key you selected", w)
				return
			} else {
				dialog.ShowInformation("Infomation", "The file is verifyed and signed by the public key you selected", w)
			}
		}
	})
	actbtn.Disable()

	return container.NewBorder(
		container.NewGridWithColumns(
			3,
			backbtn,
			widget.NewLabel("Files - Public key - Verify"),
			widget.NewLabel(""),
		),
		actbtn,
		nil,
		nil,
		container.NewPadded(
			container.New(
				layout.NewFormLayout(),
				widget.NewLabel("File"),
				container.NewGridWithColumns(
					2,
					path_wid,
					widget.NewButton("Select file", func() {
						dialog.ShowFileOpen(func(uc fyne.URIReadCloser, err error) {
							if uc == nil {
								return
							}
							if err != nil {
								show_err(w)
								return
							}

							path = uc.URI().Path()
							path_wid.SetText(uc.URI().Name())
							if path_key != "" && path != "" && path_sig != "" {
								actbtn.Enable()
							} else {
								actbtn.Disable()
							}
						}, w)
					}),
				),
				widget.NewLabel("Public key"),
				container.NewGridWithColumns(
					2,
					path_wid_key,
					widget.NewButton("Select file", func() {
						dialog.ShowFileOpen(func(uc fyne.URIReadCloser, err error) {
							if uc == nil {
								return
							}
							if err != nil {
								show_err(w)
								return
							}

							path_key = uc.URI().Path()
							path_wid_key.SetText(uc.URI().Name())
							if path_key != "" && path != "" && path_sig != "" {
								actbtn.Enable()
							} else {
								actbtn.Disable()
							}
						}, w)
					}),
				),
				widget.NewLabel("Signature"),
				container.NewGridWithColumns(
					2,
					path_wid_sig,
					widget.NewButton("Select file", func() {
						dialog.ShowFileOpen(func(uc fyne.URIReadCloser, err error) {
							if uc == nil {
								return
							}
							if err != nil {
								show_err(w)
								return
							}

							path_sig = uc.URI().Path()
							path_wid_sig.SetText(uc.URI().Name())
							if path_key != "" && path != "" && path_sig != "" {
								actbtn.Enable()
							} else {
								actbtn.Disable()
							}
						}, w)
					}),
				),
				widget.NewLabel("Cipher"),
				sel_wid,
			),
		),
	)
}
