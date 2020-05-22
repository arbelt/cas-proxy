package main

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	echo_cas "github.com/arbelt/echo-cas"
	casbin_mw "github.com/arbelt/echo-casbin"
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	string_adapter2 "github.com/qiangmzsx/string-adapter/v2"
	"github.com/urfave/cli/v2"
	"gopkg.in/cas.v2"
)

type Config struct {
	CasURL       *url.URL
	ListenAddr   string
	UpstreamURL  []*url.URL
	AllowedUsers []string `mapstructure:"allowed_users"`
}

func makeTargets(upstream []*url.URL) []*middleware.ProxyTarget {
	out := make([]*middleware.ProxyTarget, len(upstream))
	for i, v := range upstream {
		out[i] = &middleware.ProxyTarget{
			URL: v,
		}
	}
	return out
}

var app = &cli.App{
	Name:                   "cas-proxy",
	UseShortOptionHandling: true,
	Action: func(ctx *cli.Context) error {
		var conf Config
		upstreams := ctx.StringSlice("upstream")
		conf.UpstreamURL = make([]*url.URL, len(upstreams))
		for i, v := range upstreams {
			parsed, err := url.ParseRequestURI(v)
			if err != nil {
				return err
			}
			conf.UpstreamURL[i] = parsed
		}
		conf.AllowedUsers = ctx.StringSlice("users")
		e := echo.New()
		e.HideBanner = true
		e.Use(middleware.Logger())
		e.Pre(middleware.HTTPSNonWWWRedirect())
		if ctx.IsSet("cas-url") {
			casUrl, err := url.Parse(ctx.String("cas-url"))
			if err != nil {
				return cli.Exit(err, 1)
			}
			casMw := echo_cas.New(&cas.Options{
				URL: casUrl,
			})
			log.Printf("Using CAS middleware: %s\n", casUrl)
			e.Use(casMw.All)
		}
		if len(conf.AllowedUsers) > 0 {
			mdl, err := model.NewModelFromString(basicModel)
			if err != nil {
				return cli.Exit(err, 1)
			}
			pa := string_adapter2.NewAdapter(createPolicy(conf.AllowedUsers))
			enf, err := casbin.NewEnforcer(mdl, pa)
			if err != nil {
				return cli.Exit(err, 1)
			}
			enf.LoadPolicy()
			casbinMw := casbin_mw.New(casbin_mw.Config{
				Enforcer: enf,
				UserFunc: func(c echo.Context) string {
					r := c.Request()
					return cas.Attributes(r).Get("mail")
				},
			})
			log.Printf("Using CASBIN middleware: %v\n", conf.AllowedUsers)
			e.Use(casbinMw)
		}

		targets := makeTargets(conf.UpstreamURL)
		log.Printf("Proxying traffic to %d targets: %+v\n", len(targets), conf.UpstreamURL)
		e.Use(middleware.Proxy(middleware.NewRoundRobinBalancer(targets)))
		e.Use(middleware.Secure())
		return e.Start(fmt.Sprintf(":%d", ctx.Int("port")))
	},
	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:    "upstream",
			EnvVars: []string{"UPSTREAM_URL"},
		},
		&cli.IntFlag{
			Name:    "port",
			EnvVars: []string{"PORT"},
			Value: 3000,
		},
		&cli.StringFlag{
			Name:    "cas-url",
			EnvVars: []string{"CAS_URL"},
		},
		&cli.StringSliceFlag{
			Name:    "users",
			EnvVars: []string{"ALLOWED_USERS"},
		},
	},
}

func createPolicy(users []string) string {
	var sb strings.Builder
	for _, u := range users {
		fmt.Fprintln(&sb, "p, ", strings.TrimSpace(u), ", *, *")
	}
	return sb.String()
}

var basicModel string = `

[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && keyMatch(r.obj, p.obj) && keyMatch(r.act, p.act)
`

func main() {
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
