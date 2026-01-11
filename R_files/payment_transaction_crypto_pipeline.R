validate_transaction <- function(card_number, password, transaction_value, hash_db, ecc_params) {

  # aqui fazemos a checagem / Here we do the check.
  if(!luhn_vector(card_number)) return(FALSE)
  
  # verificação de senha / password verification occurs
  if(!hash_check(password, hash_db)) return(FALSE)
  
  # simulação ECDSA / ECDS simulation
  signature_valid <- simulate_ecc(ecc_params$G_order, ecc_params$attempts, ecc_params$secret_invariant)
  if(signature_valid < ecc_params$threshold) return(FALSE)
  
  return(TRUE)
}
