# rHWID
Basic HWID Grabbing with encryption support.

## Usage Example
```rust
fn main () {
    let hwid = hwid::get_hwid(Combinations::TotalMemBytes | Combinations::HostName, "my_encryption_key").expect("[ERROR] Failed fetching HWID!");
    println!("{hwid}");
}
```
