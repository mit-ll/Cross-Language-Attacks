fn main() {
    println!("cargo:rustc-link-search=./src/init/");
    //println!("cargo:rustc-link-lib=dylib=init");
    println!("cargo:rustc-link-lib=static=init");
}
