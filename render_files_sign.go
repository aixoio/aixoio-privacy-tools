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

func render_files_sign(w fyne.Window) fyne.CanvasObject {
	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_files(w)) })
	path := ""
	path_wid := widget.NewLabel(path)
	path_key := ""
	path_wid_key := widget.NewLabel(path_key)
	opts := []string{"PGP", "RSA"}
	sel_wid := widget.NewSelect(opts, func(s string) {})
	sel_wid.SetSelectedIndex(0)

	actbtn := widget.NewButton("Sign", func() {
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

		switch sel_wid.SelectedIndex() {
		case 0: // PGP
			var wg sync.WaitGroup

			wg.Add(1)

			var out string

			go func() {
				defer wg.Done()
				var ring *crypto.Key
				ring, err = crypto.NewKeyFromArmoredReader(strings.NewReader(string(pk_key)))
				var key *crypto.Key
				key, err = ring.Unlock(PGP_PASSWORD)
				var key_ring_sign *crypto.KeyRing
				key_ring_sign, err = crypto.NewKeyRing(key)
				var sig *crypto.PGPSignature
				sig, err = key_ring_sign.SignDetached(crypto.NewPlainMessage(file_dat))
				out, err = sig.GetArmored()
			}()

			d := dialog.NewCustomWithoutButtons("Signing - "+path_wid.Text, container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()

			wg.Wait()

			d.Hide()

			if err != nil {
				show_err(w)
				return
			}

			dialog.ShowFileSave(func(uc fyne.URIWriteCloser, err error) {
				if uc == nil {
					return
				}
				if err != nil {
					show_err(w)
					return
				}

				_, err = uc.Write([]byte(out))
				if err != nil {
					show_err(w)
					return
				}

				dialog.ShowInformation("File saved", "The file was saved", w)

			}, w)
		case 1: // RSA
			var wg sync.WaitGroup

			wg.Add(1)

			var out []byte

			go func() {
				defer wg.Done()
				key := rsahelper.ExportPEMStrToPrivKey(pk_key)
				out = rsahelper.Rsa_Sign(key, file_dat)
			}()

			d := dialog.NewCustomWithoutButtons("Signing - "+path_wid.Text, container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()

			wg.Wait()

			d.Hide()

			if err != nil {
				show_err(w)
				return
			}

			dialog.ShowFileSave(func(uc fyne.URIWriteCloser, err error) {
				if uc == nil {
					return
				}
				if err != nil {
					show_err(w)
					return
				}

				_, err = uc.Write(out)
				if err != nil {
					show_err(w)
					return
				}

				dialog.ShowInformation("File saved", "The file was saved", w)

			}, w)
		}
	})
	actbtn.Disable()

	return container.NewBorder(
		container.NewGridWithColumns(
			3,
			backbtn,
			widget.NewLabel("Files - Public key - Sign"),
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
							if path_key != "" && path != "" {
								actbtn.Enable()
							} else {
								actbtn.Disable()
							}
						}, w)
					}),
				),
				widget.NewLabel("Private key"),
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
							if path_key != "" && path != "" {
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
