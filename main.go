package main

import (
	"bytes"
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ./share ./static
// ./share ./mydocs -port 8080
// -port <int>  
// -log <fp>|Stdout|Stderr
// -exclude <glob>:<glob2>:...
// -password <string>|random

// share ./static -password=<STRING>
// share ./static -log=OPTION // OPTION = {Stdout, Stderr, <fp>}
// share ./public -exclude *.pem
// share ./public -port 8080
const HttpsPort = ":433"

var Ip net.IP
var (
	Port     = flag.String("port", "8080", "specify port to listen on")
	Password = flag.String("password", "", "put content behind basic http auth, 'random' generates password")
	Exclude  = flag.String("exclude", "", "files matching the glob are not served")
	Log      = flag.String("log", "Stdout", "provide a file to log to; special names 'Stdout' and 'Stderr'")
)

func usage() {
	var callName string
	switch runtime.GOOS {
	case "windows":
		callName = "share.exe"
	case "linux", "darwin":
		callName = "./share"
	}
	const msg = `Usage: 
	%s <filepath> [options]

Options:
	-log <filepath>
		provide a file to log to; special names 'Stdout' and 'Stderr'
	-exclude <glob>:<glob>:...>
		provide glob patterns seperated by colon, matching files will be excluded
	-password <password>
		provide a custom password, "" indicates no password
	-port <port>
		provide a port to listen on
`
	fmt.Fprintf(flag.CommandLine.Output(), msg, callName)
}

func main() {
	flag.Usage = usage
	if len(os.Args) < 2 {
		usage()
		return
	}

	var fp = os.Args[1]
	fi, err := os.Stat(fp)
	if !(err == nil && !os.IsNotExist(err)) {
		log.Printf("%q is not a valid filepath.\n", fp)
	}

	if len(os.Args) > 2 {
		if err := flag.CommandLine.Parse(os.Args[2:]); err != nil {
			flag.Usage()
			return
		}
	}

	closeLog := configureLogging(*Log)
	defer closeLog()

	// add a colon before the port number
	if len(*Port) > 0 && (*Port)[0] != ':' {
		*Port = ":" + *Port
	}

	// Middleware
	var adapters []Adapter

	if *Exclude != "" {
		patterns := strings.Split(*Exclude, ":")
		adapter, err := ExcludePaths(patterns)
		if err != nil {
			log.Fatalf("-exclude: %v\n", err)
		}
		adapters = append(adapters, adapter)
	}

	if *Password != "" {
		if strings.EqualFold(*Password, "random") {
			*Password = randomString(15)
			log.Println("You can leave the user field empty.")
			log.Printf("Your random password is %s\n", *Password)
		}
		hash := sha256.Sum256([]byte(*Password))
		adapters = append(adapters, BasicAuth(hash[:], "Please enter the password."))
	}

	// register handler(s) with adapters (middleware)
	var handler http.Handler
	if fi.IsDir() {
		// TODO(liamvdv): Custom implement FileServer for custom dir overview, important for excluding files.
		handler = http.FileServer(http.Dir(fp))
	} else {	
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, fp)
		})
	}
	http.Handle("/", Adapt(handler, adapters...))

	Ip = getOutboundIp()
	log.Printf("Serving from %s\n", Ip.String()+*Port)

	if err := http.ListenAndServe(*Port, nil); err != nil {
		log.Fatal(err)
	}
}

// func formHandler(w http.ResponseWriter, r *http.Request) {
// 	fmt.Println(r.URL)
// 	if !strings.HasPrefix(r.URL.Path, "/users") {
// 		http.Error(w, "404 not found.", http.StatusNotFound)
// 		return
// 	}

// 	if r.Method != "POST" {
// 		http.Error(w, "Method not supported.", http.StatusNotFound)
// 		return
// 	}

// 	if err := r.ParseForm(); err != nil {
// 		fmt.Fprintf(w, "Invalid form. %v", err)
// 	}
// 	firstName := r.FormValue("firstName")
// 	secondName := r.FormValue("secondName")
// 	fmt.Fprintf(w, "Hi %s, %s is truely a beautiful last name!\n", firstName, secondName)
// }

// func serve() error {
// 	if *Https {
// 		srv := http.Server{
// 			Addr: HttpsPort,
// 		}

// 		_, tlsPort, err := net.SplitHostPort(HttpsPort)
// 		if err != nil {
// 			return err
// 		}
// 		go redirectToHttps(*Port, tlsPort)

// 		// TODO(liamvdv): check if cert.pem and key.pem exist
// 		return srv.ListenAndServeTLS("cert.pem", "key.pem")
// 	}
// }

func getOutboundIp() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

// https://stackoverflow.com/questions/37536006/how-do-i-rewrite-redirect-from-http-to-https-in-go
// redirectToHttps starts a http server that redirects to https.
// func redirectToHttps(httpPort, httpsPort string) {
// 	srv := http.Server{
// 		Addr: httpPort,
// 		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 			host, _, _ := net.SplitHostPort(r.Host)
// 			url := r.URL
// 			url.Host = net.JoinHostPort(host, httpsPort)
// 			url.Scheme = "https"
// 			http.Redirect(w, r, url.String(), http.StatusMovedPermanently)
// 		}),
// 	}
// 	log.Fatal(srv.ListenAndServe())
// }

func exists(fp string) bool {
	_, err := os.Stat(fp)
	return err == nil || !os.IsNotExist(err)
}

func configureLogging(to string) func() {
	var file *os.File
	var err error
	switch to {
	case "Stdout":
		file = os.Stdout
	case "Stderr":
		file = os.Stderr
	default:
		file, err = os.OpenFile(to, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
		if err != nil {
			log.Printf("Cannot log to %q: %v", to, err)
		}
	}
	log.SetOutput(file)
	return func() {
		if err := file.Close(); err != nil {
			panic(err)
		}
	}
}

// Adapter pattern stolen from medium.com/@matryer
// https://medium.com/@matryer/writing-middleware-in-golang-and-how-go-makes-it-so-much-fun-4375c1246e81
type Adapter func(http.Handler) http.Handler

func Adapt(next http.Handler, adapters ...Adapter) http.Handler {
	for _, wrap := range adapters {
		next = wrap(next)
	}
	return next
}

// Invoke to get Adapter
func BasicAuth(passwordHash []byte, msg string) Adapter {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, pass, ok := r.BasicAuth()

			hash := sha256.Sum256([]byte(pass))
			if !ok || bytes.Compare(hash[:], passwordHash) != 0 {
				w.Header().Set("WWW-Authenticate", `Basic realm="`+msg+`"`)
				w.WriteHeader(401)
				w.Write([]byte("Unauthorized.\n"))
				return
			}
			h.ServeHTTP(w, r)
		})
	}
}

func ExcludePaths(patterns []string) (Adapter, error) {
	// validate patterns
	testPath := "/abc/def/jqst.html"
	for _, pattern := range patterns {
		_, err := filepath.Match(pattern, testPath)
		if err != nil {
			return nil, err
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var path = r.URL.Path
			if path == "/" {
				path = "/index.html"
			}
			for _, pattern := range patterns {
				excl, _ := filepath.Match(pattern, path)
				if excl {
					w.WriteHeader(404)
					w.Write([]byte("404 page not found"))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}, nil
}

// content stolen from https://stackoverflow.com/a/31832326
func randomString(length int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	const (
		letterIdxBits = 6                    // 6 bits to represent a letter index
		letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
		letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
	)
	var src = rand.NewSource(time.Now().UnixNano())

	sb := strings.Builder{}
	sb.Grow(length)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := length-1, src.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = src.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			sb.WriteByte(letterBytes[idx])
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return sb.String()
}
