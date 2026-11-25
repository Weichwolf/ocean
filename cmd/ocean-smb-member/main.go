package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/Weichwolf/ocean/internal/config"
	"github.com/Weichwolf/ocean/internal/smb"
)

func main() {
	settings := flag.String("config", "/etc/ocean-smb/member.json", "Samba member configuration")
	output := flag.String("output", "/etc/samba/smb.conf", "validated Samba configuration destination")
	flag.Parse()
	member, err := config.Load(*settings, smb.Member{})
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	err = smb.Prepare(ctx, member, *output)
	cancel()
	if err != nil {
		log.Fatal(err)
	}
}
