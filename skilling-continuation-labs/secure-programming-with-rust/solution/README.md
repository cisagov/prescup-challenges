# Secure Programming with Rust

## Mini-Challenge Solution

Prior to solving the questions you should downloads the required files.

1. Open the console for `kali` and then open a Terminal instance, Firefox, and VSCode (if not already open).

2. (**kali**, **Firefox**) Browse to `https://skills.hub` and the `Hosted Files` page. You should see there is a new folder labeled `challenge` present for the mini-challenge. 

### Question 1: What is the Rust command you can use to compile a script into an executable *BUT* not run it?

During the section labeled `Rust and Cargo` there are some commands that are available with `cargo`. Of those, the command `cargo build` is mentioned and it states:

> This only compiles and creates the executable, it does not run it.

So the answer for this question is `b`: `cargo build`


### Question 2: When the code within the file `mc_buf.rs` is executed, does it cause a buffer overflow to occur under any circumstance?

4. (**kali**, **Terminal**) Still on the `Desktop`, Setup a cargo environment with the following commands

```bash
mkdir mc_buf
cd mc_buf
cargo init
mv ~/Downloads/mc_buf.rs src/main.rs
```

5. (**kali**, **Terminal**) Compile and run the script

```bash
cargo run
```

In the output you should see that the script begins executing and then a `panic` occurs. This shows that the answer to this question is `c`: `No, it will panic at runtime`


#### Question 3: What is the correct `checked` method that should be implemented in the `mc_int.rs` script to prevent an integer overflow?

6.  (**kali**, **VS Code**) Open the file `mc_int.rs` to view the code.

```rust
fn main() {
    let balance: i8 = -25;
    let withdraw: i8 = 120;

    println!("Current balance: {balance}$\n");
    println!("Attempting to withdraw: {withdraw}$...");
    
    if balance.*****.is_none() {
        println!("\nInteger underflow detected!\n");
    }
}
```

Looking at the code, you should see that its a simple script to imitate a bank withdrawl.

NOTE: the `i8` notation means that the variables are being created as 8-bit integers. This means that its range of values from min to max is from -128 to 127, so an under or overflow would occur past those values.

The variable `balance` is created as a 8-bit integer that has the value `-25`.

The variable `withdraw` is created as a 8-bit integer that has the value `120`.

It then attempts to withdraw the amount from the balance, meaning that the operation being executed is `subtraction`.

We mentioned in the lab that the method `checked_sub()` is one that checks for integer underflow on subtraction operations.

So the answer is `c`:`checked_sub(withdraw)`


#### Question 4: Given the files `mc_uaf1.rs`, `mc_uaf2.rs`, and `mc_uaf3.rs`, which one currently has the "use after free" bug present?


7. (**kali**, **Terminal**) Still on the `Desktop`, Setup a cargo environment for each of the 3 files repeating the steps below, only changing the folder names so each script has its own directory.

```bash
mkdir **folder_for_script**
cd **folder_for_script**
cargo init
mv ~/Downloads/**script** src/main.rs
cargo run
```

For example, you could use the folder name `mkdir mc_uaf1` in the commands above to create and setup a directory associated with the script `mc_uaf1.rs`

Once the executable for each script is created, we can now test it using the `valgrind` tool we discussed in the lab. 

8. (**kali**, **Terminal**) Use the `valgrind` command on each of the executables made following the same syntax used in the lab.

If we continued with the example above, we would test the executable made from the `mc_uaf1.rs` script using the following command:

```bash
valgrind ~/Desktop/mc_uaf1/target/debug/mc_uaf1
```

Repeat this process for each script. 

Once you run the valgrind tool against the executable created from the script `mc_uaf2.rs`, you should see output that is similar to the output we saw in the lab. It will show there is an error and point to where the vulnerability is.

So the answer is `b`: `mc_uaf2.rs`

