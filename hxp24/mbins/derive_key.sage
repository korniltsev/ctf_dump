p = 202750432774689774479024096223623722409

F = Zmod(p)
G.<x> = F[]

# just the accepted input values from the challenges
solutions = []

points = [*{int.from_bytes(s[:2], 'big'): int.from_bytes(s[2:], 'big') for s in solutions}.items()]

if len(points) >= 950:
	key = G.lagrange_polynomial(points)[0]

	print(f"key: {key.lift().to_bytes(16, 'big').hex()}")
