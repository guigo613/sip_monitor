cargo build --release --target wasm32-unknown-unknown
wasm-bindgen --out-dir "web\js" --target web ..\target\wasm32-unknown-unknown\release\sip_monitor.wasm
cargo build --release
cp -r .\web .\build\
cp ..\target\release\sip_monitor.exe .\build\