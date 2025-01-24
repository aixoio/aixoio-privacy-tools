package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
	"github.com/ProtonMail/gopenpgp/v3/profile"
	"github.com/aixoio/aixoio-privacy-tools/lib/passphrase"
	"github.com/aixoio/aixoio-privacy-tools/lib/rsahelper"
	"github.com/google/uuid"
)

var PGP_PASSWORD []byte = nil

func render_key_generator(w fyne.Window) fyne.CanvasObject {
	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_home(w)) })
	opts := []string{
		"PGP Elliptic-Curve Curve25519 V6",
		"PGP RSA/RSA 4092",
		"RSA 4096",
		"PGP Elliptic-Curve Curve25519 V4",
		"PGP Elliptic-Curve Curve448 V6",
		"Passphrase",
	}
	sel_wid := widget.NewSelect(opts, func(s string) {})
	sel_wid.SetSelectedIndex(0)

	emailRegex := regexp.MustCompile("^((([!#$%&'*+\\-/=?^_`{|}~\\w])|([!#$%&'*+\\-/=?^_`{|}~\\w][!#$%&'*+\\-/=?^_`{|}~\\.\\w]{0,}[!#$%&'*+\\-/=?^_`{|}~\\w]))[@]\\w+([-.]\\w+)*\\.\\w+([-.]\\w+)*)$")
	// Don't ask, it's not mine I got it from https://stackoverflow.com/questions/201323/how-can-i-validate-an-email-address-using-a-regular-expression/51332395#51332395

	nameEntey := binding.NewString()
	emailEntey := binding.NewString()
	emailEn := widget.NewEntryWithData(emailEntey)
	emailEn.Validator = func(s string) error {
		if !emailRegex.MatchString(s) {
			return fmt.Errorf("invalid format: enter a vaild email address")
		}
		return nil
	}
	nameEn := widget.NewEntryWithData(nameEntey)
	nameEn.Validator = func(s string) error {
		if len(strings.TrimSpace(s)) == 0 {
			return fmt.Errorf("invalid format: enter a name")
		}
		return nil
	}

	pgpCustomDataCon := container.New(
		layout.NewFormLayout(),
		widget.NewLabel("Name"),
		nameEn,
		widget.NewLabel("Email"),
		emailEn,
	)
	pgpCustomDataCon.Hide()

	pgpCustomCheckData := binding.NewBool()
	pgpCustomCheckData.Set(false)

	pgpCustomCon := container.New(
		layout.NewFormLayout(),
		widget.NewLabel("Custom PGP name & email?"),
		widget.NewCheckWithData("", pgpCustomCheckData),
	)

	passphLenD := binding.NewFloat()
	passphLenD.Set(float64(passphrase.DEFAULT_PASSPHRASE_LENGTH))

	entropyPhD := binding.NewFloat()
	entropyPhD.Set(0)

	strengthPhD := binding.NewString()
	strengthPhD.Set("")

	phEn := widget.NewMultiLineEntry()
	phEn.SetMinRowsVisible(6)
	phEn.Wrapping = fyne.TextWrapBreak

	passphraseStr := passphrase.GeneratePassphrase(passphrase.DEFAULT_PASSPHRASE_LENGTH)
	phEn.SetText(passphraseStr)

	calc_Entrpy := func() {
		en := passphrase.CalculateEntropy(len(phEn.Text))
		entropyPhD.Set(en)
		strengthPhD.Set(passphrase.GetStrength(en))
	}

	phEn.OnChanged = func(s string) {
		calc_Entrpy()
	}

	calc_Entrpy()

	pwdGen := func() {
		lenVal, err := passphLenD.Get()
		if err != nil {
			show_err(w, err)
			return
		}

		passphraseStr = passphrase.GeneratePassphrase(int(lenVal))
		phEn.SetText(passphraseStr)
	}

	passphLenD.AddListener(binding.NewDataListener(func() {
		pwdGen()
	}))

	passphCon := container.New(
		layout.NewFormLayout(),
		widget.NewLabel("Passphrase length"),
		container.NewGridWithColumns(
			3,
			widget.NewSliderWithData(1, 64, passphLenD),
			widget.NewLabel("Length in words:"),
			widget.NewLabelWithData(binding.NewSprintf("%.0f", passphLenD)),
		),
		widget.NewLabel("Passphrase"),
		phEn,
		widget.NewLabel("Security:"),
		container.NewGridWithColumns(
			3,
			widget.NewLabelWithData(strengthPhD),
			widget.NewLabel("Entropy:"),
			widget.NewLabelWithData(binding.FloatToString(entropyPhD)),
		),
	)
	passphCon.Hide()

	showCheck := true
	showCheckCallback := func() {
		if showCheck {
			pgpCustomCon.Show()
		} else {
			pgpCustomCon.Hide()
			pgpCustomDataCon.Hide()
			return
		}

		pgpCustomCheckDataBool, err := pgpCustomCheckData.Get()
		if err != nil {
			return
		}

		if pgpCustomCheckDataBool {
			pgpCustomDataCon.Show()
			return
		}
		pgpCustomDataCon.Hide()
	}

	pgpCustomCheckData.AddListener(binding.NewDataListener(showCheckCallback))

	sel_wid.OnChanged = func(s string) {

		showPassPh := false

		switch s {
		case opts[0], opts[1], opts[3], opts[4]:
			showCheck = true
		case opts[5]:
			showCheck = false
			showPassPh = true
		default:
			showCheck = false
		}
		showCheckCallback()
		if showPassPh {
			passphCon.Show()
		} else {
			passphCon.Hide()
		}
	}

	showCheckCallback()

	return container.NewPadded(
		container.NewBorder(
			container.NewGridWithColumns(
				3,
				backbtn,
				widget.NewLabel("Key generator"),
				widget.NewLabel(""),
			),
			widget.NewButton("Generate", func() {
				var pri_key, pub_key string
				var wg sync.WaitGroup
				var err error

				if err := nameEn.Validate(); err != nil && !pgpCustomDataCon.Hidden {
					show_err(w, err)
					return
				}

				if err := emailEn.Validate(); err != nil && !pgpCustomDataCon.Hidden {
					show_err(w, err)
					return
				}

				name := uuid.NewString()
				email := uuid.NewString()

				if !pgpCustomDataCon.Hidden {
					newName, err := nameEntey.Get()
					if err != nil {
						show_err(w, err)
					}
					name = newName

					newEmail, err := emailEntey.Get()
					if err != nil {
						show_err(w, err)
					}
					email = newEmail
				}

				wg.Add(1)

				switch sel_wid.SelectedIndex() {
				case 0: // ECC
					go func() {
						defer wg.Done()
						pgpCryptoRefresh := crypto.PGPWithProfile(profile.RFC9580())
						keyGenHandle := pgpCryptoRefresh.KeyGeneration().AddUserId(name, email).New()
						ecKey, err2 := keyGenHandle.GenerateKey()
						if err2 != nil {
							err = err2
							return
						}
						pub_key, err = ecKey.GetArmoredPublicKey()
						if err != nil {
							return
						}
						pri_key, err = ecKey.Armor()
					}()

					d := dialog.NewCustomWithoutButtons("Generating your keys", container.NewPadded(
						widget.NewProgressBarInfinite(),
					), w)

					d.Show()

					wg.Wait()

					d.Hide()

					if err != nil {
						fmt.Println(err)
						show_err(w, err)
						return
					}

					dialog.ShowFolderOpen(func(lu fyne.ListableURI, err error) {
						if lu == nil {
							return
						}
						if err != nil {
							show_err(w, err)
							return
						}
						path := lu.Path()

						err = os.WriteFile(fmt.Sprintf("%s/private.asc", path), []byte(pri_key), 0644)
						if err != nil {
							show_err(w, err)
							return
						}

						err = os.WriteFile(fmt.Sprintf("%s/public.asc", path), []byte(pub_key), 0644)
						if err != nil {
							show_err(w, err)
							return
						}

						dialog.ShowInformation("Infomation", "Your key pair was saved on the "+lu.Name(), w)

					}, w)
				case 1: // PGP RSA 4092
					go func() {
						defer wg.Done()
						pgp4880 := crypto.PGPWithProfile(profile.RFC4880())
						keyGenHandle := pgp4880.KeyGeneration().AddUserId(name, email).New()
						rsaKeyHigh, err2 := keyGenHandle.GenerateKeyWithSecurity(constants.HighSecurity)
						if err2 != nil {
							err = err2
							return
						}
						pub_key, err2 = rsaKeyHigh.GetArmoredPublicKey()
						if err2 != nil {
							err = err2
							return
						}
						pri_key, err = rsaKeyHigh.Armor()
					}()

					d := dialog.NewCustomWithoutButtons("Generating your keys", container.NewPadded(
						widget.NewProgressBarInfinite(),
					), w)

					d.Show()

					wg.Wait()

					d.Hide()

					if err != nil {
						show_err(w, err)
						return
					}

					dialog.ShowFolderOpen(func(lu fyne.ListableURI, err error) {
						if lu == nil {
							return
						}
						if err != nil {
							show_err(w, err)
							return
						}
						path := lu.Path()

						err = os.WriteFile(fmt.Sprintf("%s/private.asc", path), []byte(pri_key), 0644)
						if err != nil {
							show_err(w, err)
							return
						}

						err = os.WriteFile(fmt.Sprintf("%s/public.asc", path), []byte(pub_key), 0644)
						if err != nil {
							show_err(w, err)
							return
						}

						dialog.ShowInformation("Infomation", "Your key pair was saved on the "+lu.Name(), w)

					}, w)
				case 2: // RSA 4096
					go func() {
						defer wg.Done()
						pri, pub, err2 := rsahelper.GenerateRSAKeyPair(4096)
						if err2 != nil {
							err = err2
							return
						}
						pri_key, err = rsahelper.ExportPrivKeyAsPEMStr(pri)
						if err != nil {
							return
						}
						pub_key, err = rsahelper.ExportPubkeyAsPEMStr(pub)
						if err != nil {
							return
						}
					}()

					d := dialog.NewCustomWithoutButtons("Generating your keys", container.NewPadded(
						widget.NewProgressBarInfinite(),
					), w)

					d.Show()

					wg.Wait()

					d.Hide()

					if err != nil {
						show_err(w, err)
						return
					}

					dialog.ShowFolderOpen(func(lu fyne.ListableURI, err error) {
						if lu == nil {
							return
						}
						if err != nil {
							show_err(w, err)
							return
						}
						path := lu.Path()

						err = os.WriteFile(fmt.Sprintf("%s/private.ark", path), []byte(pri_key), 0644) // .ark = aixoio rsa key
						if err != nil {
							show_err(w, err)
							return
						}

						err = os.WriteFile(fmt.Sprintf("%s/public.ark", path), []byte(pub_key), 0644) // .ark = aixoio rsa key
						if err != nil {
							show_err(w, err)
							return
						}

						dialog.ShowInformation("Infomation", "Your key pair was saved on the "+lu.Name(), w)

					}, w)
				case 3: // ECC v4
					go func() {
						defer wg.Done()
						pgpDefault := crypto.PGPWithProfile(profile.Default())
						keyGenHandle := pgpDefault.KeyGeneration().AddUserId(name, email).New()
						ecKey, err2 := keyGenHandle.GenerateKey()
						if err2 != nil {
							err = err2
							return
						}
						pub_key, err = ecKey.GetArmoredPublicKey()
						if err != nil {
							return
						}
						pri_key, err = ecKey.Armor()
					}()

					d := dialog.NewCustomWithoutButtons("Generating your keys", container.NewPadded(
						widget.NewProgressBarInfinite(),
					), w)

					d.Show()

					wg.Wait()

					d.Hide()

					if err != nil {
						fmt.Println(err)
						show_err(w, err)
						return
					}

					dialog.ShowFolderOpen(func(lu fyne.ListableURI, err error) {
						if lu == nil {
							return
						}
						if err != nil {
							show_err(w, err)
							return
						}
						path := lu.Path()

						err = os.WriteFile(fmt.Sprintf("%s/private.asc", path), []byte(pri_key), 0644)
						if err != nil {
							show_err(w, err)
							return
						}

						err = os.WriteFile(fmt.Sprintf("%s/public.asc", path), []byte(pub_key), 0644)
						if err != nil {
							show_err(w, err)
							return
						}

						dialog.ShowInformation("Infomation", "Your key pair was saved on the "+lu.Name(), w)

					}, w)
				case 4: // ECC v6 curve448
					go func() {
						defer wg.Done()
						pgpCryptoRefresh := crypto.PGPWithProfile(profile.RFC9580())
						keyGenHandle := pgpCryptoRefresh.KeyGeneration().AddUserId(name, email).New()
						ecKey, err2 := keyGenHandle.GenerateKeyWithSecurity(constants.HighSecurity)
						if err2 != nil {
							err = err2
							return
						}
						pub_key, err = ecKey.GetArmoredPublicKey()
						if err != nil {
							return
						}
						pri_key, err = ecKey.Armor()
					}()

					d := dialog.NewCustomWithoutButtons("Generating your keys", container.NewPadded(
						widget.NewProgressBarInfinite(),
					), w)

					d.Show()

					wg.Wait()

					d.Hide()

					if err != nil {
						fmt.Println(err)
						show_err(w, err)
						return
					}

					dialog.ShowFolderOpen(func(lu fyne.ListableURI, err error) {
						if lu == nil {
							return
						}
						if err != nil {
							show_err(w, err)
							return
						}
						path := lu.Path()

						err = os.WriteFile(fmt.Sprintf("%s/private.asc", path), []byte(pri_key), 0644)
						if err != nil {
							show_err(w, err)
							return
						}

						err = os.WriteFile(fmt.Sprintf("%s/public.asc", path), []byte(pub_key), 0644)
						if err != nil {
							show_err(w, err)
							return
						}

						dialog.ShowInformation("Infomation", "Your key pair was saved on the "+lu.Name(), w)

					}, w)
				case 5:
					pwdGen()
				}
			}),
			nil,
			nil,
			container.New(
				layout.NewFormLayout(),
				widget.NewLabel("Key type"),
				sel_wid,
				widget.NewLabel(""),
				pgpCustomCon,
				widget.NewLabel(""),
				pgpCustomDataCon,
				widget.NewLabel(""),
				passphCon,
			),
		),
	)
}
