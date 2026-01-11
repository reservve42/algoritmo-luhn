simulate_ecc <- function(G_order, attempts=1e6, secret_invariant) {
  successes <- 0
  for(i in 1:attempts) {
    k1 <- sample(1:G_order, 1)
    k2 <- sample(1:G_order, 1)
    derived <- (k1 * k2) %% G_order
    if(derived == secret_invariant) successes <- successes + 1
  }
  successes / attempts
}
