// pass-indexer copies a pass  (https://www.passwordstore.org/) password store
// into a folder with the secrets ASCII-armor encoded, and an encrypted index.
//
//     Usage of pass-indexer:
//       -keyring string
//         	Location of the PGP keyring. (default "$HOME/.gnupg/pubring.gpg")
//       -store string
//         	Location of the password store. (default "$HOME/.password-store")
//       -target string
//         	Target directory to generate pass-site files in. (default "$HOME/.pass-site")
package main // import "luit.eu/pass-server/cmd/pass-indexer"

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

func main() {
	home := os.ExpandEnv("$HOME")
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

	keyring := path.Join(home, ".gnupg", "pubring.gpg")
	store := path.Join(home, ".password-store")
	target := path.Join(home, ".pass-site")
	fs.StringVar(&keyring, "keyring", keyring, "Location of the PGP keyring.")
	fs.StringVar(&store, "store", store, "Location of the password store.")
	fs.StringVar(&target, "target", target, "Target directory to generate pass-site files in.")

	_ = fs.Parse(os.Args[1:])

	ids, err := readIDs(store)
	if err != nil {
		log.Fatalln(err)
	}

	el, err := readKeyring(keyring)
	if err != nil {
		log.Fatalln(err)
	}

	el, err = matchKeys(el, ids...)
	if err != nil {
		log.Fatalln(err)
	}

	err = makeTarget(store, target, el)
	if err != nil {
		log.Fatalln(err)
	}
}

func readIDs(store string) (ids []string, err error) {
	f, err := os.Open(path.Join(store, ".gpg-id"))
	if err != nil {
		return nil, err
	}
	s := bufio.NewScanner(f)
	for s.Scan() {
		id := s.Text()
		if id == "" {
			continue
		}
		ids = append(ids, id)
	}
	if s.Err() != nil {
		return ids, s.Err()
	}
	err = f.Close()
	return
}

func readKeyring(keyring string) (el openpgp.EntityList, err error) {
	f, err := os.Open(keyring)
	if err != nil {
		return nil, err
	}
	defer func() {
		e := f.Close()
		if e != nil && err == nil {
			err = e
		}
	}()
	el, err = openpgp.ReadKeyRing(f)
	return
}

func matchKeys(el openpgp.EntityList, ids ...string) (openpgp.EntityList, error) {
	rv := make(openpgp.EntityList, 0, len(ids))
key:
	for _, id := range ids {
		for _, entity := range el {
			if id == entity.PrimaryKey.KeyIdString() ||
				id == entity.PrimaryKey.KeyIdShortString() {
				rv = append(rv, entity)
				continue key
			}
		}
		return rv, errors.New("key with ID " + id + " not found")
	}
	return rv, nil
}

func makeTarget(store string, target string, el openpgp.EntityList) error {
	secrets := make([]string, 0, 16)
	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() && info.Name() == ".git" {
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}
		if filepath.Dir(path) == store {
			return nil
		}
		if match, _ := filepath.Match("*.gpg", info.Name()); match {
			secrets = append(secrets, path)
		}
		return nil
	}
	type item struct {
		Domain             string `json:"domain"`
		Path               string `json:"path"`
		Username           string `json:"username"`
		UsernameNormalized string `json:"username_normalized"`
	}
	list := make([]item, 0, len(secrets))
	err := filepath.Walk(store, walkFn)
	for _, secret := range secrets {
		secret = strings.TrimSuffix(strings.TrimPrefix(secret, store), ".gpg")
		username := path.Base(secret)
		secret = strings.TrimPrefix(path.Dir(secret), "/")
		domain := path.Base(secret)
		list = append(list, item{
			Domain:             domain,
			Path:               secret,
			Username:           username,
			UsernameNormalized: normalize(username),
		})
	}
	index := &bytes.Buffer{}
	e := json.NewEncoder(index)
	err = e.Encode(list)
	if err != nil {
		return err
	}
	err = armorSecrets(store, target, secrets...)
	if err != nil {
		return err
	}
	err = writeIndex(target, el, index)
	return err
}

func armorSecrets(store string, target string, secrets ...string) error {
	for _, secret := range secrets {
		dir := strings.TrimPrefix(path.Dir(secret), store)
		err := os.MkdirAll(path.Join(target, dir), 0700)
		if err != nil {
			return err
		}
		input, err := os.Open(secret)
		if err != nil {
			return err
		}
		defer func() { _ = input.Close() }()
		output := &bytes.Buffer{}
		w, err := armor.Encode(output, "PGP MESSAGE", nil)
		if err != nil {
			return err
		}
		_, err = io.Copy(w, input)
		if err != nil {
			return err
		}
		err = w.Close()
		if err != nil {
			return err
		}
		filename := strings.TrimSuffix(path.Base(secret), ".gpg") + ".asc"
		err = ioutil.WriteFile(path.Join(target, dir, filename), output.Bytes(), 0600)
		if err != nil {
			return err
		}
	}
	return nil
}

func writeIndex(target string, el openpgp.EntityList, index io.Reader) error {
	b := &bytes.Buffer{}
	aw, err := armor.Encode(b, "PGP MESSAGE", map[string]string{})
	if err != nil {
		return err
	}
	w, err := openpgp.Encrypt(aw, el, nil, nil, nil)
	if err != nil {
		return err
	}
	_, err = io.Copy(w, index)
	if err != nil {
		return err
	}
	err = w.Close()
	if err != nil {
		return err
	}
	err = aw.Close()
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path.Join(target, "index.asc"), b.Bytes(), 0600)
	return err
}

func normalize(s string) string {
	rs, n, err := transform.String(norm.NFKD, s)
	if err != nil {
		return ""
	}
	b := make([]byte, 0, n)
	for i := range rs {
		if rs[i] < 0x80 {
			b = append(b, rs[i])
		}
	}
	return string(b)
}
