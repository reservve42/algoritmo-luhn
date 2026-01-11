library(digest)
hash_check <- function(senha, hash_armazenado) {
  digest(senha, algo="sha256") == hash_armazenado
}

simulate_attack <- function(G_order, attempts=1e6, known_invariant) {
  successes <- 0
  for(i in 1:attempts) {
    x <- sample(1:G_order, 1)
    y <- sample(1:G_order, 1)
    if((x*y) %% G_order == known_invariant) successes <- successes + 1
  }
  successes / attempts
}
