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

func render_text_encrypt(w fyne.Window) fyne.CanvasObject {

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

	actbtn := widget.NewButton("Encrypt", func() {
		extraInfo.Set("")

		switch sel_wid.SelectedIndex() {
		case 0: // GCM
			pwd_hash := hashing.Sha256_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte
			var err error

			go func() {
				defer wg.Done()
				out, err = aes.AesGCMEncrypt(pwd_hash, []byte(msg_in.Text))
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
		case 1: // CBC
			pwd_hash := hashing.Sha256_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte
			var err error

			go func() {
				defer wg.Done()
				out, err = aes.AesHMACCBCEncrypt(pwd_hash, []byte(msg_in.Text))
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
		case 2: // Ascon
			pwd_hash := hashing.Sha256_to_bytes_128bit([]byte(pwd_wid.Text))

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte
			var err error

			go func() {
				defer wg.Done()
				out, err = asconhelper.AsconEncrypt(pwd_hash, []byte(msg_in.Text))
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
		case 3: // Ascon80pq
			pwd_hash := hashing.Sha256_to_bytes_160bit([]byte(pwd_wid.Text))

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte
			var err error

			go func() {
				defer wg.Done()
				out, err = asconhelper.AsconEncrypt(pwd_hash, []byte(msg_in.Text))
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
		case 4: // Ascon128a
			pwd_hash := hashing.Sha256_to_bytes_128bit([]byte(pwd_wid.Text))

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte
			var err error

			go func() {
				defer wg.Done()
				out, err = asconhelper.Ascon128aEncrypt(pwd_hash, []byte(msg_in.Text))
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
		case 5: // xcha
			pwd_hash := hashing.Sha256_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte
			var err error

			go func() {
				defer wg.Done()
				out, err = xchachahelper.XChaCha20Poly1305Encrypt(pwd_hash, []byte(msg_in.Text))
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
		case 6: // twofish
			pwd_hash := hashing.Sha256_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte
			var err error

			go func() {
				defer wg.Done()
				out, err = twofish.TwofishHMACEncrypt(pwd_hash, []byte(msg_in.Text))
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
		case 7: // serpent
			pwd_hash := hashing.Sha256_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte
			var err error

			go func() {
				defer wg.Done()
				out, err = serpent.SerpentHMACEncrypt(pwd_hash, []byte(msg_in.Text))
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
		case 8: // aes+twofish+serpent
			pwd_hash, err := hashing.SHAKE256_768_to_bytes([]byte(pwd_wid.Text))
			if err != nil {
				show_err(w, err)
				return
			}

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte

			go func() {
				defer wg.Done()
				out, err = combohelper.AesTwofishSerpentEncrypt(pwd_hash, []byte(msg_in.Text))
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
		case 9: // aes+xchacha
			pwd_hash := hashing.Sha3_512_to_bytes([]byte(pwd_wid.Text))

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte
			var err error

			go func() {
				defer wg.Done()
				out, err = combohelper.AesxChaCha20Poly1305Encrypt(pwd_hash, []byte(msg_in.Text))
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

		case 10: // aes+xchacha+ascon
			pwd_hash, err := hashing.SHAKE256_640_to_bytes([]byte(pwd_wid.Text))
			if err != nil {
				show_err(w, err)
				return
			}

			var wg sync.WaitGroup
			wg.Add(1)

			var out []byte

			go func() {
				defer wg.Done()
				out, err = combohelper.AesXChaCha20Poly1305Ascon128aEncrypt(pwd_hash, []byte(msg_in.Text))
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
			widget.NewLabel("Text - Encrypt"),
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
