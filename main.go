package main

import (
	"fmt"
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
	UpstreamURL  *url.URL
	AllowedUsers []string `mapstructure:"allowed_users"`
}

var app = &cli.App{
	Name:                   "cas-proxy",
	UseShortOptionHandling: true,
	Action: func(ctx *cli.Context) error {
		var conf Config
		upstream, err := url.Parse(ctx.String("upstream"))
		if err != nil {
			fmt.Println(err)
			return err
		}
		conf.UpstreamURL = upstream
		conf.AllowedUsers = ctx.StringSlice("users")
		fmt.Printf("%v\n", conf.AllowedUsers)
		e := echo.New()
		e.Use(middleware.Logger())
		e.Pre(middleware.HTTPSNonWWWRedirect())
		if ctx.IsSet("cas-url") {
			casUrl, err := url.Parse(ctx.String("cas-url"))
			if err != nil {
				return err
			}
			casMw := echo_cas.New(&cas.Options{
				URL: casUrl,
			})
			e.Use(casMw.All)
		}
		if len(conf.AllowedUsers) > 0 {
			mdl, err := model.NewModelFromString(basicModel)
			if err != nil {
				return err
			}
			pa := string_adapter2.NewAdapter(createPolicy(conf.AllowedUsers))
			enf, err := casbin.NewEnforcer(mdl, pa)
			if err != nil {
				return err
			}
			enf.LoadPolicy()
			casbinMw := casbin_mw.New(casbin_mw.Config{
				Enforcer: enf,
				UserFunc: func(c echo.Context) string {
					r := c.Request()
					return cas.Attributes(r).Get("mail")
				},
			})
			e.Use(casbinMw)
		}
		targets := []*middleware.ProxyTarget{
			{
				URL: conf.UpstreamURL,
			},
		}
		e.Use(middleware.Proxy(middleware.NewRoundRobinBalancer(targets)))
		return e.Start(fmt.Sprintf(":%d", ctx.Int("port")))
	},
	Flags: []cli.Flag{
		&cli.StringFlag{
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
	app.Run(os.Args)
	//var c Config = loadConfig()
	//fmt.Println(c.UpstreamURL.String())
	//fmt.Println(createPolicy(c.AllowedUsers))
	//sa := scas.NewAdapter(createPolicy(c.AllowedUsers))
	//e := echo.New()
	//e.Use(middleware.Logger())
	//casMw := echo_cas.New(&cas.Options{
	//	URL: c.CasURL,
	//})
	//mdl, err := model.NewModelFromString(basicModel)
	//if err != nil {
	//	panic(err)
	//}
	//enforcer, err := casbin.NewEnforcer(mdl, sa)
	//if err != nil {
	//	panic(err)
	//}
	//e.Pre(middleware.HTTPSNonWWWRedirect())
	//e.Use(middleware.Secure())
	//enforcer.LoadPolicy()
	//casbinMw := echo_casbin.New(echo_casbin.Config{
	//	Enforcer: enforcer,
	//	UserFunc: func(ctx echo.Context) string {
	//		r := ctx.Request()
	//		return cas.Attributes(r).Get("mail")
	//	},
	//})
	//e.Use(casMw.All, casbinMw)
	//targets := []*middleware.ProxyTarget{
	//	{
	//		URL: c.UpstreamURL,
	//	},
	//}
	//e.Use(middleware.Proxy(middleware.NewRoundRobinBalancer(targets)))
	//if err := e.Start(fmt.Sprintf(":%s", viper.GetString("listen.port"))); err != nil {
	//	log.Fatal(err)
	//}
}
