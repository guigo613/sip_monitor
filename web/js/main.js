import init, { start } from "./sip_monitor.js";

async function main() {
    await init()

    start("tracevia")

    let canvas = document.getElementById("tracevia")
    canvas.style.maxHeight = window.innerHeight
    canvas.style.maxWidth = window.innerWidth

    document.addEventListener("resize", () => {
        canvas.style.maxHeight = window.innerHeight
        canvas.style.maxWidth = window.innerWidth
    })
}

main()