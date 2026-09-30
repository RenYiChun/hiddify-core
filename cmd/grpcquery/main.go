package main

import (
	"context"
	"fmt"
	"time"

	"github.com/hiddify/hiddify-core/v2/hcommon"
	"github.com/hiddify/hiddify-core/v2/hcore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func main() {
	conn, err := grpc.NewClient("127.0.0.1:17079", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Println("dial error:", err)
		return
	}
	defer conn.Close()

	client := hcore.NewCoreClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := client.OutboundsInfo(ctx, &hcommon.Empty{})
	if err != nil {
		fmt.Println("OutboundsInfo error:", err)
		return
	}
	resp, err := stream.Recv()
	if err != nil {
		fmt.Println("recv error:", err)
		return
	}
	fmt.Printf("groups returned: %d\n", len(resp.Items))
	if len(resp.Items) > 0 {
		g := resp.Items[0]
		ok, timeout, notTested := 0, 0, 0
		var okList []string
		for _, it := range g.Items {
			switch {
			case it.UrlTestDelay > 0 && it.UrlTestDelay < 65000:
				ok++
				okList = append(okList, fmt.Sprintf("%s(%dms)", it.Tag, it.UrlTestDelay))
			case it.UrlTestDelay >= 65000:
				timeout++
			default:
				notTested++
			}
		}
		fmt.Printf("group[0] %q: total=%d ok=%d timeout=%d notTested=%d\n", g.Tag, len(g.Items), ok, timeout, notTested)
		fmt.Println("usable:")
		for _, s := range okList {
			fmt.Println("  " + s)
		}
		fmt.Println("all nodes:")
		for _, it := range g.Items {
			status := "TIMEOUT"
			if it.UrlTestDelay > 0 && it.UrlTestDelay < 65000 {
				status = fmt.Sprintf("%5dms", it.UrlTestDelay)
			} else if it.UrlTestDelay == 0 {
				status = "  n/a  "
			}
			fmt.Printf("  %s  %s\n", status, it.Tag)
		}
	}
}
