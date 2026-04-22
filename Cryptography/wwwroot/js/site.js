document.addEventListener("DOMContentLoaded", () => {
	const HISTORY_KEY = "cryptography.resultHistory.v1";
	const HISTORY_LIMIT = 20;
	const cipherType = document.getElementById("cipherType");
	const caesarShiftGroup = document.getElementById("caesarShiftGroup");
	const vigenereKeyGroup = document.getElementById("vigenereKeyGroup");
	const permutationKeyGroup = document.getElementById("permutationKeyGroup");
	const monoalphabeticKeyGroup = document.getElementById("monoalphabeticKeyGroup");
	const playfairKeyGroup = document.getElementById("playfairKeyGroup");
	const hillKeyGroup = document.getElementById("hillKeyGroup");
	const cipherForm = document.querySelector('form[asp-action="Index"], form[action*="ClassicalCiphers"]') || document.querySelector("form");
	const outputTextElement = document.getElementById("outputText");
	const outputBadgeElement = document.querySelector(".output-badge");
	const historyContainer = document.getElementById("resultHistory");
	const emptyHistoryElement = document.getElementById("resultHistoryEmpty");
	const clearHistoryBtn = document.getElementById("clearHistoryBtn");
	const gateLinks = document.querySelectorAll(".gate-link");

	function toggleCipherFields() {
		if (!cipherType) {
			return;
		}

		const selected = cipherType.value;
		if (caesarShiftGroup) {
			caesarShiftGroup.style.display = selected === "caesar" ? "block" : "none";
		}
		if (vigenereKeyGroup) {
			vigenereKeyGroup.style.display = selected === "vigenere" ? "block" : "none";
		}
		if (permutationKeyGroup) {
			permutationKeyGroup.style.display = selected === "permutation" ? "block" : "none";
		}
		if (monoalphabeticKeyGroup) {
			monoalphabeticKeyGroup.style.display = selected === "monoalphabetic" ? "block" : "none";
		}
		if (playfairKeyGroup) {
			playfairKeyGroup.style.display = selected === "playfair" ? "block" : "none";
		}
		if (hillKeyGroup) {
			hillKeyGroup.style.display = selected === "hill" ? "block" : "none";
		}
	}

	if (cipherType) {
		cipherType.addEventListener("change", toggleCipherFields);
		toggleCipherFields();
	}

	if (cipherForm) {
		cipherForm.addEventListener("submit", () => {
			document.body.classList.add("no-motion");
		});
	}

	function getHistory() {
		try {
			const raw = localStorage.getItem(HISTORY_KEY);
			if (!raw) {
				return [];
			}

			const parsed = JSON.parse(raw);
			return Array.isArray(parsed) ? parsed : [];
		} catch {
			return [];
		}
	}

	function saveHistory(history) {
		localStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, HISTORY_LIMIT)));
	}

	function clearHistory() {
		localStorage.removeItem(HISTORY_KEY);
	}

	function renderHistory() {
		if (!historyContainer) {
			return;
		}

		const history = getHistory();

		historyContainer.querySelectorAll(".history-item").forEach((item) => item.remove());

		if (emptyHistoryElement) {
			emptyHistoryElement.style.display = history.length === 0 ? "block" : "none";
		}

		history.forEach((entry) => {
			const item = document.createElement("div");
			item.className = "history-item";

			const meta = document.createElement("div");
			meta.className = "history-meta";
			meta.textContent = `${entry.badge} - ${entry.time}`;

			const output = document.createElement("pre");
			output.className = "history-output";
			output.textContent = entry.output;

			item.appendChild(meta);
			item.appendChild(output);
			historyContainer.appendChild(item);
		});
	}

	function pushCurrentResultToHistory() {
		if (!outputTextElement || !outputBadgeElement) {
			return;
		}

		const output = outputTextElement.textContent?.trim();
		const badge = outputBadgeElement.textContent?.trim();
		if (!output || !badge) {
			return;
		}

		const history = getHistory();
		const last = history[0];
		if (last && last.output === output && last.badge === badge) {
			return;
		}

		const time = new Date().toLocaleString("vi-VN");
		history.unshift({ badge, output, time });
		saveHistory(history);
	}

	pushCurrentResultToHistory();
	renderHistory();

	if (clearHistoryBtn) {
		clearHistoryBtn.addEventListener("click", () => {
			clearHistory();
			renderHistory();
		});
	}

	if (gateLinks.length > 0) {
		gateLinks.forEach((gateLink) => {
			gateLink.addEventListener("click", (event) => {
				const destination = gateLink.getAttribute("href");
				if (!destination) {
					return;
				}

				event.preventDefault();
				if (gateLink.classList.contains("gate-opening")) {
					return;
				}

				gateLink.classList.add("gate-opening");
				window.setTimeout(() => {
					window.location.href = destination;
				}, 850);
			});
		});
	}
});
