#!/bin/bash

# Couleurs
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RESET="\033[0m"

IP="127.0.0.1"

EXPECTED_HELP="test/help_expected.txt"

COUNT_OK=0
COUNT_FAIL=0

assert_diff() {
	local output="$1"        # Contenu réel produit par le programme
	local expected_file="$2" # Fichier contenant la sortie attendue
	local label="$3"         # Label du test (ex: "./ft_nmap --help")
	local expected_exit="$4" # Code de sortie attendu
	local actual_exit="$5"   # Code de sortie réel

	# 1) Vérif du contenu avec diff
	local diff_ok=0
	diff -q "$expected_file" "$output" >/dev/null
	local diff_exit_code=$?
	if [ "$diff_exit_code" -eq 0 ]; then
		diff_ok=1
	fi

	# 2) Vérif du code de sortie
	local exit_ok=0
	if [ -n "$expected_exit" ] && [ "$actual_exit" -eq "$expected_exit" ]; then
		exit_ok=1
	fi

	# 3) Résultat combiné
	if [ $diff_ok -eq 1 ] && [ $exit_ok -eq 1 ]; then
		echo -e "${GREEN}✅ $label OK${RESET}"
		((COUNT_OK++))
		return 0
	else
		echo -e "${RED}❌ $label FAIL${RESET}"
		((COUNT_FAIL++))

		if [ $diff_ok -eq 0 ]; then
			echo -e "${YELLOW}----- Diff -----${RESET}"
			diff --color "$expected_file" "$output"
			echo -e "${YELLOW}----------------${RESET}"
		fi

		if [ $exit_ok -eq 0 ]; then
			echo -e "${RED}⚠ Exit code mismatch (got ${actual_exit}, expected ${expected_exit})${RESET}"
		fi

		return 1
	fi
}

print_summary() {
	echo -e "\n${YELLOW}===== TEST SUMMARY =====${RESET}"
	echo -e "${GREEN}✅ OK: $COUNT_OK${RESET}"
	echo -e "${RED}❌ FAIL: $COUNT_FAIL${RESET}"
	echo -e "${YELLOW}======================${RESET}"
}

# === Référence avec nmap ===
nmap -sS -p 70-90 --reason -oG - $IP |
	awk -v scan="SYN" '
/Ports:/ {
  split($0, parts, "Ports: ")
  split(parts[2], ports, ", ")
  for (i in ports) {
    split(ports[i], f, "/")
    port = f[1]
    state = f[2]
    proto = f[3]
    service = (f[5] == "" ? "Unassigned" : f[5])

    # mapping nmap → ft_nmap style
    if (state == "open") {
      printf "%s %s %s(Open) Open\n", port, service, scan
    } else if (state == "closed") {
      printf "%s %s %s(Closed) Closed\n", port, service, scan
    } else if (state == "filtered") {
      printf "%s %s %s(Filtered) Filtered\n", port, service, scan
    } else {
      printf "%s %s %s(%s) %s\n", port, service, scan, state, state
    }
  }
}' | sort -n >ref.txt

# === Sortie de ft_nmap ===
# ./ft_nmap --ip $IP --ports 70-90 --scan SYN |
# 	awk '/^[0-9]/ {print}' | sort -n >out.txt

# === Diff ===
# echo "=== DIFF ==="
# diff -u ref.txt out.txt

declare -a COMMANDS_HELP_OK=(
	"./ft_nmap --help"
	"./ft_nmap --ip $IP --help"
	"./ft_nmap --help --ip $IP"
	"./ft_nmap --ip $IP --ports 1-10 --help"
	"./ft_nmap --ip $IP --speedup 10 --help"
	"./ft_nmap --ip $IP --help --scan SYN"
	"./ft_nmap --ip $IP --scan SYN --ports 1-10 --speedup 10 --help"
)

declare -a COMMANDS_KO=(
	"./ft_nmap --ports 1-10"
	"./ft_nmap --speedup 10"
	"./ft_nmap --scan SYN"
)

for cmd in "${COMMANDS_HELP_OK[@]}"; do
	echo "▶️ Running: $cmd"
	$cmd >output
	RET=$?
	assert_diff output "$EXPECTED_HELP" "HELP format ($cmd)" 0 "$RET"
done

for cmd in "${COMMANDS_KO[@]}"; do
	echo "▶️ $cmd"
	$cmd >output 2>/dev/null
	RET=$?
	assert_diff output "$EXPECTED_HELP" "Usage shown for missing --ip/file ($cmd)" 1 "$RET"
done

rm -f output

print_summary
