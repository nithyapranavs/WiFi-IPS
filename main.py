import attack
import automate_attack
import detection
import audit
import wardriver
import time

def menu():
    while True:
            print("\n--- Main Menu ---")
            print("1) Attack Mode")
            print("2) Automate Attack Mode")
            print("3) Defence Mode")
            print("4) Reconnaissance")
            print("5) Exit")

            choice = input("Enter your choice: ")

            if choice == '1':
                attack.offensive_menu()
            elif choice == '2':
                automate_attack.run()
            elif choice == '3':
                print("Secure AP enabled")
                detection.start_detection()
            elif choice == '4':
                print("\n--- Reconnaissance Menu ---")
                print("1) Audit")
                print("2) War Drive")
                print("3) Back to Main Menu")

                recon_choice = input("Enter your choice: ")

                if recon_choice == '1':
                    audit.audit_networks()
                elif recon_choice == '2':
                    wardriver.start()
                elif recon_choice == '3':
                    continue
                else:
                    print("Invalid choice. Try again.")
            elif choice == '5':
                print("Exiting...")
                break
            else:
                print("Invalid choice. Try again.")

            time.sleep(1)

if __name__ == "__main__":
    menu()
