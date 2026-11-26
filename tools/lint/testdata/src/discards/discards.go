package discards

import (
	parse "encoding/json"
	"os"

	client "go.etcd.io/etcd/client/v3"
)

var _ = os.WriteFile("test", nil, 0600) // want `check the error returned by os.WriteFile`

func check(file *os.File, decoder *parse.Decoder, transaction client.Txn) error {
	var data string
	_ = (parse.Unmarshal(nil, &data)) // want `check the error returned by encoding/json.Unmarshal`
	_, _ = 0, decoder.Decode(&data)   // want `check the error returned by \(\*encoding/json.Decoder\).Decode`
	_ = file.Sync()                   // want `check the error returned by \(\*os.File\).Sync`
	_, _ = transaction.Commit()       // want `check the error returned by \(go.etcd.io/etcd/client/v3.Txn\).Commit`
	_ = file.Close()
	_, err := transaction.Commit()
	return err
}
