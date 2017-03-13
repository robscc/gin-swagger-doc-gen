package main

import (
	"gopkg.in/urfave/cli.v1"
	"os"
)

func main() {
	app := cli.NewApp()

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "router_path",
			Value: "./main.go",
			Usage: "router define path ,default ./main.go",
		},
		cli.StringFlag{
			Name:  "output_path",
			Value: "./",
			Usage: "output swagger path ,default ./",
		},
	}

	app.Action = func(c *cli.Context) {
		routerPath := c.String("router_path")
		outputPath := c.String("output_path")

		generateDocs(routerPath, outputPath)
	}

	app.Run(os.Args)
}
