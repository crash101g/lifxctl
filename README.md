# lifxctl

Find, control, watch and troubleshoot LIFX lights from Linux, without the phone app.

I have a LIFX LED strip behind my TV that keeps showing it is not responding in the LIFX smartphone app. The only fix
was unplugging it and plugging it back in. `lifxctl` talks to the lights directly over your home
network (the LIFX LAN protocol on UDP 56700), so it works even when the app says a light is offline.
It also helps you work out *why* a light keeps dropping off or turning itself off.

Single Python file, no dependencies (Python 3.8+). Built and used on Pop!_OS / Ubuntu.

## What it does

- **Find lights.** It broadcasts like the app does, sweeps your /24, and checks ARP. Every light
  it finds is saved (IP, MAC, name, firmware, last seen), so a light that disappears or changes IP
  is noticed.
- **Control.** On/off, reboot (then wait for it to come back and turn it on), and LIFX scenes.
- **Scenes.** It can use the scenes saved in your LIFX app (needs a cloud API token). If the cloud
  is down it applies them over the LAN from a saved copy. It also saves local snapshots that keep
  every zone of a strip gradient.
- **Health.** Firmware vs LIFX's latest release, Wi-Fi signal (dBm), uptime and packet loss.
- **Watch.** Logs `DOWN`, `BACK`, `REBOOTED` (power loss or crash) and `POWER on -> off`
  (something sent an off command), with timestamps and how long each outage lasted.
- **Diagnose.** Runs every check and prints a ranked "what to do" list.
- **Interactive menu.** Run it with no arguments.

## Install

```bash
git clone https://github.com/crash101g/lifxctl.git
cd lifxctl
./lifxctl.py            # interactive menu
```

Optional: `sudo ln -s "$PWD/lifxctl.py" /usr/local/bin/lifxctl`

Your PC must be on the same LAN/subnet as the lights.

## Quick start

```bash
./lifxctl.py scan                    # find all LIFX lights
./lifxctl.py on                      # all on
./lifxctl.py off "tv strip"          # by name, IP or MAC
./lifxctl.py reboot "tv strip" --then-on
./lifxctl.py diagnose                # why does it keep dropping off / turning off?
./lifxctl.py watch --interval 60     # leave running, then check the log
```

## Commands

| Command | What it does |
|---|---|
| *(none)* / `menu` | Interactive menu |
| `scan` | Broadcast + subnet sweep + ARP check. Lists saved lights that aren't answering |
| `known` | Saved lights and whether each answers right now |
| `status [targets]` | Power, product and name |
| `on` / `off [targets]` | Default target is all. `--fade MS` |
| `reboot <targets\|all>` | Reboots, waits up to 60 s for it to return. `--then-on`, `--no-wait` |
| `firmware [targets]` | Firmware vs LIFX's latest, Wi-Fi dBm, uptime |
| `diagnose` | Discovery path, packet loss, signal, reboots, power-offs, IP changes, outage history, plus fixes |
| `guide` | Troubleshooting guide: symptoms, causes, router settings, reset steps |
| `watch` | Logs DOWN / BACK / MISSING / REBOOTED / POWER events. `--interval`, `--misses` |
| `token` | Save your LIFX cloud token (for app scenes) |
| `scenes [--refresh]` | List scenes from your LIFX app and local ones |
| `scene <name\|#>` | Activate. Uses the cloud, falls back to the LAN. `--local-only`, `--duration` |
| `scene-save <name> [targets]` | Snapshot the current look locally, including strip zones |
| `scene-delete <name>` | Delete a local scene |
| `forget <target>` | Remove a light from the saved list |

A target is an IP, a MAC (`d0:73:d5:…`), part of a light's name, or `all`.

Global options: `--subnet 192.168.1.0/24`, `--no-sweep`, `-v` (log every packet), `-q`,
`--log FILE`, `--no-log`, `--cache FILE`.

## Scenes from the LIFX app

App scenes live in your LIFX cloud account, not on the lights. Create a personal access token at
<https://cloud.lifx.com/settings>, then:

```bash
./lifxctl.py token        # paste it (input is hidden). Saved to ~/.config/lifxctl/token, mode 600
./lifxctl.py scenes
./lifxctl.py scene "movie night"
```

The cloud API stores one color per light, so a multi-color strip gradient comes back as a single
color. To save one exactly, set it in the app, then run `./lifxctl.py scene-save "TV gradient"`.

## Troubleshooting: why does my LIFX light drop off / turn off?

Run `./lifxctl.py diagnose` (or `guide` for the full write-up). It sorts things into:

| What you see | What it means | Usual fix |
|---|---|---|
| Script sees it, app doesn't | Router drops discovery broadcasts | Turn off AP/client isolation and IGMP snooping/multicast filtering; phone and lights on the same network |
| `DOWN … gone from ARP` | Light fell off Wi-Fi | Signal (move the controller out from behind the TV), separate 2.4 GHz network (no band steering), WPA2-AES, no AX-only on 2.4 GHz, fixed channel 1/6/11 at 20 MHz, mesh steering off, DHCP reservation |
| In ARP but not answering | Light's software is hung | `reboot`, else power cycle; update firmware |
| `REBOOTED` | Lost power or crashed | Check the strip's power adapter and connectors; not on a TV USB port or switched/timer outlet |
| `POWER on -> off`, no reboot | Something sent it an "off" | LIFX app schedules/routines, Alexa / Google / Apple Home automations, integrations |

Leave `watch` running for a day, then run `diagnose` again: it reads the log and points out
patterns, such as drop-offs that always happen around the same hour.

## Files

| Path | Contents |
|---|---|
| `~/.local/state/lifxctl/lifxctl.log` | Log (1 MB × 5, rotated) |
| `~/.local/state/lifxctl/devices.json` | Saved lights |
| `~/.local/state/lifxctl/scenes.json` | App scene cache + local scenes |
| `~/.config/lifxctl/token` | LIFX cloud token (mode 600, never written to the log) |

## Limits

- A light that has fully dropped off Wi-Fi can't be reached by anything on the network: not
  this script, not the app. Power cycling is the only fix. A smart plug lets you automate that.
- Firmware can only be installed from the LIFX app. This script only reports what's available.
- Not affiliated with or endorsed by LIFX.

## License

GPL-3.0. See [LICENSE](LICENSE).
