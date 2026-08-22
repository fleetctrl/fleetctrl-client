package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	backend := NewUIBackend()
	err := wails.Run(&options.App{
		Title:            "FleetCtrl",
		Width:            1180,
		Height:           760,
		MinWidth:         900,
		MinHeight:        620,
		DisableResize:    false,
		Frameless:        false,
		BackgroundColour: &options.RGBA{R: 226, G: 234, B: 249, A: 0},
		AssetServer:      &assetserver.Options{Assets: assets},
		OnStartup:        backend.Startup,
		Bind:             []any{backend},
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId: "fleetctl-ui-91bf5ebf-3a32-43e9-bd9c-cbcefb58d57c",
			OnSecondInstanceLaunch: func(secondInstanceData options.SecondInstanceData) {
				wailsruntime.WindowUnminimise(backend.ctx)
				wailsruntime.WindowShow(backend.ctx)
			},
		},
		Windows: &windows.Options{
			WebviewIsTransparent: true,
			WindowIsTranslucent:  true,
			DisableWindowIcon:    false,
			Theme:                windows.SystemDefault,
			BackdropType:         windows.Acrylic,
			CustomTheme: &windows.ThemeSettings{
				// oklch(0.163 0.012 262) / oklch(0.978 0.003 258) z --background ve styles.css
				DarkModeTitleBar:           windows.RGB(11, 14, 19),
				DarkModeTitleBarInactive:   windows.RGB(11, 14, 19),
				DarkModeTitleText:          windows.RGB(156, 163, 175),
				DarkModeTitleTextInactive:  windows.RGB(156, 163, 175),
				DarkModeBorder:             windows.RGB(11, 14, 19),
				DarkModeBorderInactive:     windows.RGB(11, 14, 19),
				LightModeTitleBar:          windows.RGB(246, 248, 250),
				LightModeTitleBarInactive:  windows.RGB(246, 248, 250),
				LightModeTitleText:         windows.RGB(107, 114, 128),
				LightModeTitleTextInactive: windows.RGB(107, 114, 128),
				LightModeBorder:            windows.RGB(246, 248, 250),
				LightModeBorderInactive:    windows.RGB(246, 248, 250),
			},
			Messages: &windows.Messages{
				InstallationRequired: "Pro spuštění FleetCtrl je potřeba WebView2 Runtime. Po potvrzení se stáhne a nainstaluje.",
				UpdateRequired:       "WebView2 Runtime je potřeba aktualizovat. Po potvrzení se aktualizace stáhne a nainstaluje.",
				MissingRequirements:  "Chybí součást systému",
				Webview2NotInstalled: "WebView2 Runtime není nainstalovaný",
				Error:                "Chyba",
				FailedToInstall:      "WebView2 Runtime se nepodařilo nainstalovat. Obraťte se na správce zařízení.",
				DownloadPage:         "FleetCtrl vyžaduje WebView2 Runtime. Potvrzením otevřete stránku ke stažení.",
				PressOKToInstall:     "Potvrzením zahájíte instalaci.",
				ContactAdmin:         "WebView2 Runtime je nutný ke spuštění FleetCtrl. Obraťte se na správce zařízení.",
				InvalidFixedWebview2: "Nastavený WebView2 Runtime není platný.",
				WebView2ProcessCrash: "Proces WebView2 se ukončil. Spusťte FleetCtrl znovu.",
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}
}
