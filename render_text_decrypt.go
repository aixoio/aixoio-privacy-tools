package main

import (
	"encoding/base64"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/binding"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/aixoio/aixoio-privacy-tools/lib/aes"
	"github.com/aixoio/aixoio-privacy-tools/lib/asconhelper"
	"github.com/aixoio/aixoio-privacy-tools/lib/combohelper"
	"github.com/aixoio/aixoio-privacy-tools/lib/hashing"
	"github.com/aixoio/aixoio-privacy-tools/lib/serpent"
	"github.com/aixoio/aixoio-privacy-tools/lib/twofish"
	"github.com/aixoio/aixoio-privacy-tools/lib/xchachahelper"
)

func render_text_decrypt(w fyne.Window) fyne.CanvasObject {

	backbtn := widget.NewButtonWithIcon("Back to menu", theme.NavigateBackIcon(), func() { w.SetContent(render_text(w)) })
	pwd_wid := widget.NewPasswordEntry()
	opts := []string{"AES-256 Bit GCM with SHA256", "AES-256 Bit CBC with SHA256 and HMAC-SHA256", "Ascon 128-bit with SHA256 truncated", "Ascon80pq 160-bit with SHA256 truncated", "Ascon128a 128-bit with SHA256 truncated", "xChaCha20-Poly1305 with SHA256", "Twofish 256-bit with SHA256 and HMAC-SHA256", "Serpent 256-bit with SHA256 and HMAC-SHA256", "AES+Twofish+Serpent", "AES+xChaCha20", "AES+xChaCha20+Ascon128a"}
	extraInfo := binding.NewString()
	extraInfo.Set("")
	sel_wid := widget.NewSelect(opts, func(s string) {
		switch s {
		case opts[8]:
			extraInfo.Set(combohelper.AES_TWOFISH_SERPENT_EXPLAIN)
		case opts[9]:
			extraInfo.Set(combohelper.AES_XCHACHA_EXPLAIN)
		case opts[10]:
			extraInfo.Set(combohelper.AES_XCHACHA_ASCONA_EXPLAIN)
		default:
			extraInfo.Set("")

		}
	})
	sel_wid.SetSelectedIndex(0)

	msg_in := widget.NewMultiLineEntry()
	msg_in.Wrapping = fyne.TextWrapBreak
	msg_in.SetMinRowsVisible(6)

	actbtn := widget.NewButton("Decrypt", func() {

		switch sel_wid.SelectedIndex() {
		case 0: // GCM
			pwd_hash := hashing.Sha256_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte
			var err error

			dat, err := base64.StdEncoding.DecodeString(msg_in.Text)
			if err != nil {
				show_err(w, err)
				return
			}

			go func() {
				defer wg.Done()
				out, err = aes.AesGCMDecrypt(pwd_hash, dat)
			}()

			d := dialog.NewCustomWithoutButtons("Decrypting - Your message", container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()
			wg.Wait()
			d.Hide()
			if err != nil {
				show_err(w, err)
				return
			}

			msg_in.SetText(string(out))
		case 1: // CBC
			pwd_hash := hashing.Sha256_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte
			var err error

			dat, err := base64.StdEncoding.DecodeString(msg_in.Text)
			if err != nil {
				show_err(w, err)
				return
			}

			go func() {
				defer wg.Done()
				out, err = aes.AesHMACCBCDecrypt(pwd_hash, dat)
			}()

			d := dialog.NewCustomWithoutButtons("Decrypting - Your message", container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()
			wg.Wait()
			d.Hide()
			if err != nil {
				show_err(w, err)
				return
			}

			msg_in.SetText(string(out))
		case 2: // Ascon
			pwd_hash := hashing.Sha256_to_bytes_128bit([]byte(pwd_wid.Text))

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte
			var err error

			dat, err := base64.StdEncoding.DecodeString(msg_in.Text)
			if err != nil {
				show_err(w, err)
				return
			}

			go func() {
				defer wg.Done()
				out, err = asconhelper.AsconDecrypt(pwd_hash, dat)
			}()

			d := dialog.NewCustomWithoutButtons("Decrypting - Your message", container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()
			wg.Wait()
			d.Hide()
			if err != nil {
				show_err(w, err)
				return
			}

			msg_in.SetText(string(out))
		case 3: // Ascon80pq
			pwd_hash := hashing.Sha256_to_bytes_160bit([]byte(pwd_wid.Text))

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte
			var err error

			dat, err := base64.StdEncoding.DecodeString(msg_in.Text)
			if err != nil {
				show_err(w, err)
				return
			}

			go func() {
				defer wg.Done()
				out, err = asconhelper.AsconDecrypt(pwd_hash, dat)
			}()

			d := dialog.NewCustomWithoutButtons("Decrypting - Your message", container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()
			wg.Wait()
			d.Hide()
			if err != nil {
				show_err(w, err)
				return
			}

			msg_in.SetText(string(out))
		case 4: // Ascon128a
			pwd_hash := hashing.Sha256_to_bytes_128bit([]byte(pwd_wid.Text))

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte
			var err error

			dat, err := base64.StdEncoding.DecodeString(msg_in.Text)
			if err != nil {
				show_err(w, err)
				return
			}

			go func() {
				defer wg.Done()
				out, err = asconhelper.Ascon128aDecrypt(pwd_hash, dat)
			}()

			d := dialog.NewCustomWithoutButtons("Decrypting - Your message", container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()
			wg.Wait()
			d.Hide()
			if err != nil {
				show_err(w, err)
				return
			}

			msg_in.SetText(string(out))
		case 5: // xcha
			pwd_hash := hashing.Sha256_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte
			var err error

			dat, err := base64.StdEncoding.DecodeString(msg_in.Text)
			if err != nil {
				show_err(w, err)
				return
			}

			go func() {
				defer wg.Done()
				out, err = xchachahelper.XChaCha20Poly1305Decrypt(pwd_hash, dat)
			}()

			d := dialog.NewCustomWithoutButtons("Decrypting - Your message", container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()
			wg.Wait()
			d.Hide()
			if err != nil {
				show_err(w, err)
				return
			}

			msg_in.SetText(string(out))
		case 6: // twofish
			pwd_hash := hashing.Sha256_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte
			var err error

			dat, err := base64.StdEncoding.DecodeString(msg_in.Text)
			if err != nil {
				show_err(w, err)
				return
			}

			go func() {
				defer wg.Done()
				out, err = twofish.TwofishHMACDecrypt(pwd_hash, dat)
			}()

			d := dialog.NewCustomWithoutButtons("Decrypting - Your message", container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()
			wg.Wait()
			d.Hide()
			if err != nil {
				show_err(w, err)
				return
			}

			msg_in.SetText(string(out))
		case 7: // serpent
			pwd_hash := hashing.Sha256_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte
			var err error

			dat, err := base64.StdEncoding.DecodeString(msg_in.Text)
			if err != nil {
				show_err(w, err)
				return
			}

			go func() {
				defer wg.Done()
				out, err = serpent.SerpentHMACDecrypt(pwd_hash, dat)
			}()

			d := dialog.NewCustomWithoutButtons("Decrypting - Your message", container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()
			wg.Wait()
			d.Hide()
			if err != nil {
				show_err(w, err)
				return
			}

			msg_in.SetText(string(out))
		case 8: // aes+twofish+serpent
			pwd_hash, err := hashing.SHAKE256_768_to_bytes([]byte(pwd_wid.Text))
			if err != nil {
				show_err(w, err)
				return
			}

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte

			dat, err := base64.StdEncoding.DecodeString(msg_in.Text)
			if err != nil {
				show_err(w, err)
				return
			}

			go func() {
				defer wg.Done()
				out, err = combohelper.AesTwofishSerpentDecrypt(pwd_hash, dat)
			}()

			d := dialog.NewCustomWithoutButtons("Decrypting - Your message", container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()
			wg.Wait()
			d.Hide()
			if err != nil {
				show_err(w, err)
				return
			}

			msg_in.SetText(string(out))
		case 9: // aes+twofish+serpent
			pwd_hash := hashing.Sha3_512_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte
			var err error

			dat, err := base64.StdEncoding.DecodeString(msg_in.Text)
			if err != nil {
				show_err(w, err)
				return
			}

			go func() {
				defer wg.Done()
				out, err = combohelper.AesxChaCha20Poly1305Decrypt(pwd_hash, dat)
			}()

			d := dialog.NewCustomWithoutButtons("Decrypting - Your message", container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()
			wg.Wait()
			d.Hide()
			if err != nil {
				show_err(w, err)
				return
			}

			msg_in.SetText(string(out))
		case 10: // aes+xchacha+ascon
			pwd_hash, err := hashing.SHAKE256_640_to_bytes([]byte(pwd_wid.Text))
			if err != nil {
				show_err(w, err)
				return
			}

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte

			dat, err := base64.StdEncoding.DecodeString(msg_in.Text)
			if err != nil {
				show_err(w, err)
				return
			}

			go func() {
				defer wg.Done()
				out, err = combohelper.AesXChaCha20Poly1305Ascon128aDecrypt(pwd_hash, dat)
			}()

			d := dialog.NewCustomWithoutButtons("Decrypting - Your message", container.NewPadded(
				widget.NewProgressBarInfinite(),
			), w)

			d.Show()
			wg.Wait()
			d.Hide()
			if err != nil {
				show_err(w, err)
				return
			}

			msg_in.SetText(string(out))

		}

	})
	actbtn.Disable()

	msg_in.OnChanged = func(s string) {
		if len(s) != 0 && len(pwd_wid.Text) != 0 {
			actbtn.Enable()
		} else {
			actbtn.Disable()
		}
	}

	pwd_wid.OnChanged = func(s string) {
		if len(s) != 0 && len(msg_in.Text) != 0 {
			actbtn.Enable()
		} else {
			actbtn.Disable()
		}
	}

	return container.NewBorder(
		container.NewGridWithColumns(
			3,
			backbtn,
			widget.NewLabel("Text - Decrypt"),
			widget.NewLabel(""),
		),
		actbtn,
		nil,
		nil,
		container.NewPadded(
			container.New(
				layout.NewFormLayout(),
				widget.NewLabel("Password"),
				pwd_wid,
				widget.NewLabel("Cipher"),
				sel_wid,
				widget.NewLabel("Message"),
				msg_in,
				widget.NewLabel(""),
				widget.NewLabelWithData(extraInfo),
			),
		),
	)

}
