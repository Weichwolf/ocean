package clientv3

type Txn interface {
	Commit() (*TxnResponse, error)
}

type TxnResponse struct{}
