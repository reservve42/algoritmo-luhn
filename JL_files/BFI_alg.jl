using Random
using Plots

function simulate_dlp(group_order, attempts = 1_000_000)
    secret = rand(1:group_order) 
    success = false
    
    for _ in 1:attempts
        guess = rand(1:group_order) 
        if guess == secret
            success = true
            break
        end
    end
    return success
end

function simulate_and_plot(group_order, max_attempts)
    successes = Float64[]  
    attempts_range = 1:max_attempts

    for attempts in attempts_range
        success_count = sum(simulate_dlp(group_order, attempts) for _ in 1:100)
        push!(successes, success_count / 100.0) 
    end
    
    plot(attempts_range, successes, xlabel="N° tentativas", ylabel="Pr(A) sucesso",
         label="Probabilidade", title="Simulação de  BFI para DLP", legend=:topright)
end


group_order = 2^10 

max_attempts = 100

simulate_and_plot(group_order, max_attempts)

