document.addEventListener("DOMContentLoaded", () => {
	const cipherType = document.getElementById("cipherType");
	const caesarShiftGroup = document.getElementById("caesarShiftGroup");
	const vigenereKeyGroup = document.getElementById("vigenereKeyGroup");

	function toggleCipherFields() {
		if (!cipherType || !caesarShiftGroup || !vigenereKeyGroup) {
			return;
		}

		const selected = cipherType.value;
		caesarShiftGroup.style.display = selected === "caesar" ? "block" : "none";
		vigenereKeyGroup.style.display = selected === "vigenere" ? "block" : "none";
	}

	if (cipherType) {
		cipherType.addEventListener("change", toggleCipherFields);
		toggleCipherFields();
	}

	const revealElements = document.querySelectorAll(".reveal-on-scroll");
	if ("IntersectionObserver" in window) {
		const observer = new IntersectionObserver((entries) => {
			entries.forEach((entry) => {
				if (entry.isIntersecting) {
					entry.target.classList.add("is-visible");
					observer.unobserve(entry.target);
				}
			});
		}, { threshold: 0.12 });

		revealElements.forEach((element) => observer.observe(element));
	} else {
		revealElements.forEach((element) => element.classList.add("is-visible"));
	}
});
