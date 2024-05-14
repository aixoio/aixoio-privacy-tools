package main

import (
	"fmt"
	"os"
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

func render_key_generator(w fyne.Window) fyne.CanvasObject {
	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_home(w)) })
	opts := []string{"PGP Elliptic-Curve Curve25519 x25519", "PGP RSA/RSA 4096", "RSA 4096"}
	sel_wid := widget.NewSelect(opts, func(s string) {})
	sel_wid.SetSelectedIndex(0)

	return container.NewBorder(
		container.NewGridWithColumns(
			3,
			backbtn,
			widget.NewLabel("Key generator"),
			widget.NewLabel(""),
		),
		widget.NewButton("Generate key pair", func() {
			var pri_key, pub_key string
			var wg sync.WaitGroup
			var err error

			wg.Add(1)

			switch sel_wid.SelectedIndex() {
			case 0: // ECC
				go func() {
					defer wg.Done()
					var pri *crypto.Key
					pri, err = crypto.GenerateKey("PGP", "", "x25519", 0)
					pri_key, err = pri.Armor()
					pub_key, err = pri.GetArmoredPublicKey()
				}()
			case 1: // PGP RSA 4096
				go func() {
					defer wg.Done()
					var pri *crypto.Key
					pri, err = crypto.GenerateKey("PGP", "", "rsa", 4096)
					pri_key, err = pri.Armor()
					pub_key, err = pri.GetArmoredPublicKey()
				}()
			case 2: // RSA 4096
				go func() {
					defer wg.Done()
					pri, pub := rsahelper.Generate_rsa_pey_kair(4096)
					pri_key = rsahelper.ExportPrivKeyAsPEMStr(pri)
					pub_key = rsahelper.ExportPubkeyAsPEMStr(pub)
				}()
			}

			d := dialog.NewCustomWithoutButtons("Generating your keys", container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()

			wg.Wait()

			d.Hide()

			if err != nil {
				show_err(w)
				return
			}

			dialog.ShowFolderOpen(func(lu fyne.ListableURI, err error) {
				if lu == nil {
					return
				}
				if err != nil {
					show_err(w)
					return
				}
				path := lu.Path()

				err = os.WriteFile(fmt.Sprintf("%s/private.key", path), []byte(pri_key), 0644)
				if err != nil {
					show_err(w)
					return
				}

				err = os.WriteFile(fmt.Sprintf("%s/public.key", path), []byte(pub_key), 0644)
				if err != nil {
					show_err(w)
					return
				}

				dialog.ShowInformation("Infomation", "Your key pair was saved on the "+lu.Name(), w)

			}, w)
		}),
		nil,
		nil,
		container.New(
			layout.NewFormLayout(),
			widget.NewLabel("Key type"),
			sel_wid,
		),
	)
}
