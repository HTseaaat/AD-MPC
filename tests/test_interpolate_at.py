from random import randint, shuffle
from adkg.polynomial import polynomials_over
from pypairing import ZR, blsmultiexp as multiexp, dotprod
# from pypairing import Curve25519ZR as ZR, Curve25519G as G1, curve25519multiexp as multiexp, curve25519dotprod as dotprod

def test_poly_interpolate_at(galois_field, polynomial):
    # Take x^2 + 10 as the polynomial
    poly = polynomials_over(ZR)
    # values = [(i+1, pow(i+1, 2) + 10) for i in range(3)]
    values = [(1, 0x48C499FE618FB55FAB183ECAFD8C9B26591D770E8C2F75E1CB6069FC3FA6C72A), (2, 0x64842FB663FD16517AF5B2A9D52605286B95C1DA4A01D4EBEB7F194E92C815C8), 
              (3, 0xC561E1B3CCCF9FB17994E80A31D97252A5068A307D5D7F70B9DC8A1E5E96465), (4, 0x2815B3D33F3A5AECE776C25F7AB701273CC8B36EC5A837012BBC77F4390AB303)]
    print(values)
    # k = galois_field.random()
    k = 0
    res = poly.interpolate_at(values, k)
    print("k=0", res)
    # assert polynomial.interpolate_at(values, k) == pow(k, 2) + 10

    # 0 res: 0x48C499FE618FB55FAB183ECAFD8C9B26591D770E8C2F75E1CB6069FC3FA6C72A
    # 1 res: 0x64842FB663FD16517AF5B2A9D52605286B95C1DA4A01D4EBEB7F194E92C815C8
    # 2 res: 0xC561E1B3CCCF9FB17994E80A31D97252A5068A307D5D7F70B9DC8A1E5E96465
    # 3 res: 0x2815B3D33F3A5AECE776C25F7AB701273CC8B36EC5A837012BBC77F4390AB303

    
  