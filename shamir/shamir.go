/*
1. Создание полинома:
Для разделения секрета на несколько частей генерируется случайный полином степени
t−1, где t — это порог. Полином строится таким образом, что его первый коэффициент равен секрету.
Остальные коэффициенты выбираются случайным образом.
2. Распределение долей:
Каждая доля секрета — это значение полинома в разных точках (например,
𝑥1,𝑥2,…,𝑥𝑛). Эти доли передаются участникам. Каждому участнику передается пара: точка
𝑥 и значение полинома в этой точке 𝑦.
3. Восстановление секрета:
Чтобы восстановить секрет, нужно собрать хотя бы t долей, которые содержат точки полинома.
С помощью интерполяции Лагранжа можно вычислить значение полинома в точке 𝑥=0, что и даст секрет.
*/
package shamir

import (
	"crypto/rand" // генерация случайных чисел
	"crypto/subtle" // пакет для безопасных сравнений с предотвращением атак по времени
	"fmt"
	mathrand "math/rand" // генерация случайных чисел (для некриптографических целей)
	"time" // для работы с временем
)

const (
	// ShareOverhead — это накладные расходы на каждый разделенный секрет.
	// При разделении секрета добавляется один байт (тег) к каждому разделу.
	ShareOverhead = 1
)

// Структура для представления полинома
// Коэффициенты полинома — это список байтов (каждый байт — коэффициент).
type polynomial struct {
	coefficients []uint8 // список коэф.полинома
}

// makePolynomial генерирует случайный полином заданной степени с заданным интерсептом.
func makePolynomial(intercept, degree uint8) (polynomial, error) {
	// Создание полинома с случайными коэффициентами
	p := polynomial{
		coefficients: make([]byte, degree+1), // Массив для хранения коэффициентов полинома
	}

	// Устанавление интерсепт (начальный коэффициент)
	p.coefficients[0] = intercept

	// Генерирование случайных коэффициентов для полинома
	if _, err := rand.Read(p.coefficients[1:]); err != nil {
		return p, err
	}

	return p, nil
}

// evaluate вычисляет значение полинома в точке x.
func (p *polynomial) evaluate(x uint8) uint8 {
	// Особый случай, если x = 0, то возвращается только интерсепт
	if x == 0 {
		return p.coefficients[0]
	}

	// Вычисление значения полинома с использованием метода Хорнера
	degree := len(p.coefficients) - 1
	out := p.coefficients[degree]
	for i := degree - 1; i >= 0; i-- {
		coeff := p.coefficients[i]
		// Применение метода Хорнера для вычисления значения полинома
		out = add(mult(out, x), coeff)
	}
	return out
}

// interpolatePolynomial выполняет интерполяцию полинома с использованием Lagrange интерполяции.
func interpolatePolynomial(x_samples, y_samples []uint8, x uint8) uint8 {
	limit := len(x_samples) // Количество точек для интерполяции
	var result, basis uint8
	// Перебираются все образцы для выполнения интерполяции
	for i := 0; i < limit; i++ {
		basis = 1
		// Для каждой точки вычисляется ее вклад в итоговое значение
		for j := 0; j < limit; j++ {
			if i == j {
				continue
			}
			// Вычисляется числитель и знаменатель для лагранжева базисного полинома
			num := add(x, x_samples[j])
			denom := add(x_samples[i], x_samples[j])
			// Вычисляется и умножается на базисный коэффициент
			term := div(num, denom)
			basis = mult(basis, term)
		}
		// Умножается на y-значение для текущей точки и добавляется к результату
		group := mult(y_samples[i], basis)
		result = add(result, group)
	}
	return result
}

// div делит два числа в поле GF(2^8) (расширенная версия поля Галуа).
func div(a, b uint8) uint8 {
	if b == 0 {
		// Если делитель равен нулю, выбрасывается исключение
		panic("divide by zero")
	}

	// Получение результата деления с использованием умножения на обратное число
	ret := int(mult(a, inverse(b)))

	// Возвращается 0, если a = 0 (предотвращает атаки по времени)
	ret = subtle.ConstantTimeSelect(subtle.ConstantTimeByteEq(a, 0), 0, ret)
	return uint8(ret)
}

// inverse вычисляет обратное число для числа в GF(2^8).
func inverse(a uint8) uint8 {
	// Использование метода возведения в степень для нахождения обратного элемента
	b := mult(a, a)
	c := mult(a, b)
	b = mult(c, c)
	b = mult(b, b)
	c = mult(b, c)
	b = mult(b, b)
	b = mult(b, b)
	b = mult(b, c)
	b = mult(b, b)
	b = mult(a, b)

	return mult(b, b)
}

// mult умножает два числа в поле GF(2^8).
func mult(a, b uint8) (out uint8) {
	var r uint8 = 0
	var i uint8 = 8

	// Использование метода умножения в поле Галуа
	for i > 0 {
		i--
		// умножение с помощью алгоритма Галуа
		r = (-(b >> i & 1) & a) ^ (-(r >> 7) & 0x1B) ^ (r + r)
	}

	return r
}

// add складывает два числа в поле GF(2^8). Это также работает как вычитание, потому что операция симметрична.
func add(a, b uint8) uint8 {
	return a ^ b
}

// Split разделяет секрет на части, где для восстановления секрета требуется определенное количество частей (порог).
func Split(secret []byte, parts, threshold int) ([][]byte, error) {
	// Проверка корректности входных данных
	if parts < threshold {
		return nil, fmt.Errorf("parts cannot be less than threshold")
	}
	if parts > 255 {
		return nil, fmt.Errorf("parts cannot exceed 255")
	}
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be at least 2")
	}
	if threshold > 255 {
		return nil, fmt.Errorf("threshold cannot exceed 255")
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("cannot split an empty secret")
	}

	// Генерация случайных x-координат
	mathrand.Seed(time.Now().UnixNano())
	xCoordinates := mathrand.Perm(255)

	// Выделение памяти для частей секрета, добавление тега к каждой части
	out := make([][]byte, parts)
	for idx := range out {
		out[idx] = make([]byte, len(secret)+1)
		out[idx][len(secret)] = uint8(xCoordinates[idx]) + 1
	}

	// Для каждого байта секрета создается полином
	for idx, val := range secret {
		// Генерация полинома для каждого байта секрета
		p, err := makePolynomial(val, uint8(threshold-1))
		if err != nil {
			return nil, fmt.Errorf("failed to generate polynomial: %w", err)
		}

		// Генерация частей секрета для каждого байта
		for i := 0; i < parts; i++ {
			x := uint8(xCoordinates[i]) + 1
			y := p.evaluate(x)
			out[i][idx] = y
		}
	}

	// Возвращение разделенного секрета
	return out, nil
}

// Combine восстанавливает секрет из частей, если число частей больше или равно порогу.
func Combine(parts [][]byte) ([]byte, error) {
	// Проверка, что частей достаточно для восстановления секрета
	if len(parts) < 2 {
		return nil, fmt.Errorf("less than two parts cannot be used to reconstruct the secret")
	}

	// Проверка, что все части имеют одинаковую длину
	firstPartLen := len(parts[0])
	if firstPartLen < 2 {
		return nil, fmt.Errorf("parts must be at least two bytes")
	}
	for i := 1; i < len(parts); i++ {
		if len(parts[i]) != firstPartLen {
			return nil, fmt.Errorf("all parts must be the same length")
		}
	}

	// Буфер для восстановленного секрета
	secret := make([]byte, firstPartLen-1)

	// Буферы для хранения точек (x, y)
	x_samples := make([]uint8, len(parts))
	y_samples := make([]uint8, len(parts))

	// Проверка уникальности x-координат
	checkMap := map[byte]bool{}
	for i, part := range parts {
		samp := part[firstPartLen-1]
		if exists := checkMap[samp]; exists {
			return nil, fmt.Errorf("duplicate part detected")
		}
		checkMap[samp] = true
		x_samples[i] = samp
	}

	// Восстановление каждого байта секрета
	for idx := range secret {
		// Сбор точек (x, y) для интерполяции
		for i, part := range parts {
			y_samples[i] = part[idx]
		}

		// Интерполяция полинома и вычисление значения для x = 0
		val := interpolatePolynomial(x_samples, y_samples, 0)

		// Восстановление значения секрета для текущего байта
		secret[idx] = val
	}

	// Возвращение восстановленного секрета
	return secret, nil
}
