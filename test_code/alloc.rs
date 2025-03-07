fn main() {
    let mut karina = vec![];
    for i in 0..100 {
        karina.push(i);
    }

    println!("{}", karina.iter().sum::<usize>());
}
