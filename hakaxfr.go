package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

func main() {
	nameserver := flag.String("ns", "8.8.8.8", "nameserver to use for DNS lookups")
	concurrencyPtr := flag.Int("t", 8, "Number of threads to utilise. Default is 8.")
	flag.Parse()

	numWorkers := *concurrencyPtr
	work := make(chan string)
	go func() {
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			work <- s.Text()
		}
		close(work)
	}()

	wg := &sync.WaitGroup{}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go AXFR(*nameserver, work, wg)
	}
	wg.Wait()
}

// AXFR attempts a zone transfer for the domain.
func AXFR(serverAddr string, work chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for domain := range work {
		servers, err := LookupNS(domain, serverAddr)
		if err != nil {
			log.Println("Error lookup up NS record:", err)
		}

		for _, s := range servers {
			tr := dns.Transfer{}
			m := &dns.Msg{}
			m.SetAxfr(dns.Fqdn(domain))
			in, err := tr.In(m, s+":53")
			if err != nil {
				log.Println("Error querying NS:", err)
			}
			for ex := range in {
				for _, a := range ex.RR {
					var hostname string
					switch v := a.(type) {
					case *dns.A:
						hostname = v.Hdr.Name
					case *dns.AAAA:
						hostname = v.Hdr.Name
					case *dns.PTR:
						hostname = v.Ptr
					case *dns.NS:
						cip, err := LookupName(v.Ns, serverAddr)
						if err != nil || len(cip) == 0 {
							continue
						}
						hostname = v.Ns
					case *dns.CNAME:
						cip, err := LookupName(v.Target, serverAddr)
						if err != nil || len(cip) == 0 {
							continue
						}
						hostname = v.Hdr.Name
					case *dns.SRV:
						cip, err := LookupName(v.Target, serverAddr)
						if err != nil || len(cip) == 0 {
							continue
						}
						hostname = v.Target
					default:
						continue
					}

					// print the hostnames
					fmt.Println(strings.TrimRight(hostname, "."))
				}
			}
		}
	}
}

// LookupNS returns the names servers for a domain.
func LookupNS(domain, serverAddr string) ([]string, error) {
	servers := []string{}
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	in, err := dns.Exchange(m, serverAddr+":53")
	if err != nil {
		return servers, err
	}
	if len(in.Answer) < 1 {
		return servers, errors.New("no Answer")
	}
	for _, a := range in.Answer {
		if ns, ok := a.(*dns.NS); ok {
			servers = append(servers, ns.Ns)
		}
	}
	return servers, nil
}

// LookupName returns IPv4 addresses from A records or error.
func LookupName(fqdn, serverAddr string) ([]string, error) {
	ips := []string{}
	m := &dns.Msg{}
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	in, err := dns.Exchange(m, serverAddr+":53")
	if err != nil {
		return ips, err
	}
	if len(in.Answer) < 1 {
		return ips, errors.New("no Answer")
	}
	for _, answer := range in.Answer {
		if a, ok := answer.(*dns.A); ok {
			ip := a.A.String()
			ips = append(ips, ip)
		}
	}

	if len(ips) == 0 {
		err = errors.New("no A record returned")
	}
	sort.Strings(ips)
	return ips, err
}
