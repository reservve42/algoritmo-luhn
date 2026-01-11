luhn_vector <- function(numero) {
  d <- as.integer(strsplit(numero, "")[[1]])
  d <- rev(d)
  weights <- rep(c(1,2), length.out = length(d))
  d_weighted <- d * weights
  d_weighted <- ifelse(d_weighted > 9, d_weighted - 9, d_weighted)
  sum(d_weighted) %% 10 == 0
}
