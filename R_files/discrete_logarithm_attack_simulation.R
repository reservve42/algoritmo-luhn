simulate_dlp <- function(group_order, attempts = 1e6) {
  secret <- sample(1:group_order, 1)
  success <- FALSE
  
  for (i in 1:attempts) {
    guess <- sample(1:group_order, 1)
    if (guess == secret) {
      success <- TRUE
      break
    }
  }
  success
}
