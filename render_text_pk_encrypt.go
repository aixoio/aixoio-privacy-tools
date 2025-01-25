package main

import (
	"encoding/base64"
	"os"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/aixoio/aixoio-privacy-tools/lib/rsahelper"
)

func render_text_pk_encrypt(w fyne.Window) fyne.CanvasObject {
	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_text(w)) })
	path_key := ""
	path_wid_key := widget.NewLabel(path_key)
	opts := []string{"PGP", "RSA"}
	sel_wid := widget.NewSelect(opts, func(s string) {})
	sel_wid.SetSelectedIndex(0)

	msg_in := widget.NewMultiLineEntry()
	msg_in.Wrapping = fyne.TextWrapBreak
	msg_in.SetMinRowsVisible(6)

	actbtn := widget.NewButton("Encrypt", func() {
		key_dat, err := os.ReadFile(path_key)
		if err != nil {
			show_err(w, err)
			return
		}

		switch sel_wid.SelectedIndex() {
		case 0: // PGP
			var wg sync.WaitGroup

			wg.Add(1)

			publicKey, err := crypto.NewKeyFromArmored(string(key_dat))
			if err != nil {
				show_err(w, err)
				return
			}
			pgp := crypto.PGP()
			encHandle, err := pgp.Encryption().Recipient(publicKey).New()
			if err != nil {
				show_err(w, err)
				return
			}

			var pgpMessage *crypto.PGPMessage

			go func() {
				defer wg.Done()
				pgpMessage, err = encHandle.Encrypt([]byte(msg_in.Text))
			}()

			d := dialog.NewCustomWithoutButtons("Encrypting - Your message", container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()

			wg.Wait()

			d.Hide()

			if err != nil {
				show_err(w, err)
				return
			}

			publicKey.ClearPrivateParams()

			armored, err := pgpMessage.ArmorBytes()
			if err != nil {
				show_err(w, err)
				return
			}

			msg_in.SetText(string(armored))
		case 1: // RSA
			var wg sync.WaitGroup

			wg.Add(1)

			var out []byte

			go func() {
				defer wg.Done()
				key, err2 := rsahelper.ExportPEMStrToPubKey(key_dat)
				if err2 != nil {
					err = err2
					return
				}
				out, err = rsahelper.RsaEncrypt(key, []byte(msg_in.Text))
			}()

			d := dialog.NewCustomWithoutButtons("Encrypting - Your message", container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()

			wg.Wait()

			d.Hide()

			if err != nil {
				show_err(w, err)
				return
			}

			out_str := base64.StdEncoding.EncodeToString(out)

			msg_in.SetText(out_str)
		}
	})
	actbtn.Disable()

	msg_in.OnChanged = func(s string) {
		if path_key != "" && s != "" {
			actbtn.Enable()
		} else {
			actbtn.Disable()
		}
	}

	return container.NewBorder(
		container.NewGridWithColumns(
			3,
			backbtn,
			widget.NewLabel("Text - Public key - Encrypt"),
			widget.NewLabel(""),
		),
		actbtn,
		nil,
		nil,
		container.NewPadded(
			container.New(
				layout.NewFormLayout(),
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
								show_err(w, err)
								return
							}

							path_key = uc.URI().Path()
							path_wid_key.SetText(uc.URI().Name())
							if path_key != "" && msg_in.Text != "" {
								actbtn.Enable()
							} else {
								actbtn.Disable()
							}
						}, w)
					}),
				),
				widget.NewLabel("Cipher"),
				sel_wid,
				widget.NewLabel("Message"),
				msg_in,
			),
		),
	)
}
