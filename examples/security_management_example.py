"""
Exemple d'utilisation du gestionnaire de sécurité SSRS PowerBI
"""

import os
import urllib3
from ssrs_library import SSRSRestClient
from ssrs_library.security_manager import SSRSSecurityManager
from dotenv import load_dotenv

load_dotenv()
urllib3.disable_warnings()


def example_rls_management():
    """Exemple de gestion RLS (Row Level Security)"""

    # Configuration
    server_url = os.getenv("SSRS_SERVER_URL")
    username = os.getenv("SSRS_USERNAME")
    password = os.getenv("SSRS_PASSWORD")
    domain = os.getenv("SSRS_DOMAIN")

    if not all([server_url, username, password]):
        raise ValueError("Missing required environment variables")

    # Initialisation du client
    client = SSRSRestClient(
        server_url=server_url,
        username=username,
        password=password,
        domain=domain,
        verify_ssl=False,
    )

    security_manager = SSRSSecurityManager(client)

    # Test de connexion
    if not client.test_connection():
        print("❌ Failed to connect to SSRS server")
        return

    print("✅ Connected to SSRS server")

    # 1. Migrer les assignations de rôles RLS entre rapports
    print("\n🔄 Migration des assignations RLS...")

    source_report = "/Demo/Test Report"
    target_report = "/Demo/Production Report"

    success = security_manager.migrate_data_model_role_assignments(
        source_report, target_report
    )

    if success:
        print(f"✅ Migration RLS réussie de {source_report} vers {target_report}")
    else:
        print("❌ Échec de la migration RLS")

    # 2. Lister les assignations actuelles
    print(f"\n📋 Assignations RLS pour {target_report}:")
    assignments = security_manager.list_role_assignments(target_report)

    for username, roles in assignments.items():
        print(f"  👤 {username}: {', '.join(roles)}")

    # 3. Ajouter un utilisateur à un rôle
    print("\n➕ Ajout d'un utilisateur au rôle...")
    success = security_manager.add_user_to_role(
        report_path=target_report,
        username="DOMAIN\\testuser",
        role_names=["Sales Region"],
    )

    if success:
        print("✅ Utilisateur ajouté avec succès")
    else:
        print("❌ Échec de l'ajout de l'utilisateur")


def example_folder_security_management():
    """Exemple de gestion de sécurité au niveau dossier"""

    client = SSRSRestClient(
        server_url=os.getenv("SSRS_SERVER_URL"),
        username=os.getenv("SSRS_USERNAME"),
        password=os.getenv("SSRS_PASSWORD"),
        domain=os.getenv("SSRS_DOMAIN"),
        verify_ssl=False,
    )

    security_manager = SSRSSecurityManager(client)

    # 1. Copier les permissions d'un dossier vers un autre
    print("🔄 Copie des permissions de dossier...")

    source_folder = "/Demo/Test Folder"
    target_folder = "/Demo/Production Folder"

    success = security_manager.copy_folder_permissions(source_folder, target_folder)

    if success:
        print(f"✅ Permissions copiées de {source_folder} vers {target_folder}")
    else:
        print("❌ Échec de la copie des permissions")

    # 2. Récupérer les permissions d'un dossier
    print(f"\n📋 Permissions pour {source_folder}:")
    permissions = security_manager.get_folder_permissions(source_folder)

    if permissions:
        for permission in permissions:
            print(f"  🔐 {permission}")
    else:
        print("  ⚠️ Aucune permission trouvée")


def example_catalog_item_policies():
    """Exemple de gestion des politiques d'éléments de catalogue"""

    client = SSRSRestClient(
        server_url=os.getenv("SSRS_SERVER_URL"),
        username=os.getenv("SSRS_USERNAME"),
        password=os.getenv("SSRS_PASSWORD"),
        domain=os.getenv("SSRS_DOMAIN"),
        verify_ssl=False,
    )

    security_manager = SSRSSecurityManager(client)

    # 1. Migrer les politiques entre éléments
    print("🔄 Migration des politiques de catalogue...")

    source_item = "/Demo/Test Report"
    target_item = "/Demo/Production Report"

    success = security_manager.migrate_catalog_item_policies(source_item, target_item)

    if success:
        print(f"✅ Politiques migrées de {source_item} vers {target_item}")
    else:
        print("❌ Échec de la migration des politiques")

    # 2. Récupérer les politiques d'un élément
    print(f"\n📋 Politiques pour {source_item}:")
    policies = security_manager.get_catalog_item_policies(source_item)

    if policies:
        print(f"  📄 Politiques trouvées: {len(policies.get('value', []))} éléments")
        for policy in policies.get("value", []):
            print(f"    🔐 {policy.get('GroupUserName', 'Unknown')}")
    else:
        print("  ⚠️ Aucune politique trouvée")


def example_bulk_security_operations():
    """Exemple d'opérations de sécurité en lot"""

    client = SSRSRestClient(
        server_url=os.getenv("SSRS_SERVER_URL"),
        username=os.getenv("SSRS_USERNAME"),
        password=os.getenv("SSRS_PASSWORD"),
        domain=os.getenv("SSRS_DOMAIN"),
        verify_ssl=False,
    )

    security_manager = SSRSSecurityManager(client)

    # Liste des rapports à traiter
    reports = ["/Demo/Test Report", "/Demo/Production Report", "/Demo/Another Report"]

    # Utilisateur à ajouter à tous les rapports
    user_to_add = "DOMAIN\\manager"
    roles_to_assign = ["Manager Role", "Viewer Role"]

    print(f"👥 Ajout de {user_to_add} aux rapports...")

    success_count = 0
    for report_path in reports:
        print(f"\n  📊 Traitement de {report_path}")

        # Vérifier les rôles existants
        try:
            existing_assignments = security_manager.list_role_assignments(report_path)

            if user_to_add in existing_assignments:
                print(
                    f"    ℹ️  Utilisateur déjà assigné avec rôles: {existing_assignments[user_to_add]}"
                )

            # Ajouter l'utilisateur aux rôles
            success = security_manager.add_user_to_role(
                report_path=report_path,
                username=user_to_add,
                role_names=roles_to_assign,
            )

            if success:
                print("    ✅ Utilisateur ajouté avec succès")
                success_count += 1
            else:
                print("    ❌ Échec de l'ajout de l'utilisateur")

        except Exception as e:
            print(f"    💥 Erreur: {str(e)}")

    print(f"\n📈 Résumé: {success_count}/{len(reports)} rapports traités avec succès")


def example_security_audit():
    """Exemple d'audit de sécurité"""

    client = SSRSRestClient(
        server_url=os.getenv("SSRS_SERVER_URL"),
        username=os.getenv("SSRS_USERNAME"),
        password=os.getenv("SSRS_PASSWORD"),
        domain=os.getenv("SSRS_DOMAIN"),
        verify_ssl=False,
    )

    security_manager = SSRSSecurityManager(client)

    print("🔍 Audit de sécurité SSRS PowerBI")
    print("=" * 50)

    # Liste des éléments à auditer
    items_to_audit = [
        "/Demo/Test Report",
        "/Demo/Production Report",
        "/Demo/Another Report",
    ]

    audit_results = {}

    for item_path in items_to_audit:
        print(f"\n📊 Audit de: {item_path}")

        try:
            # Audit des assignations RLS
            print("  🔐 Assignations RLS:")
            rls_assignments = security_manager.list_role_assignments(item_path)

            if rls_assignments:
                for user, roles in rls_assignments.items():
                    print(f"    👤 {user}: {', '.join(roles)}")

                audit_results[item_path] = {
                    "rls_users": len(rls_assignments),
                    "rls_assignments": rls_assignments,
                }
            else:
                print("    ⚠️  Aucune assignation RLS trouvée")
                audit_results[item_path] = {"rls_users": 0, "rls_assignments": {}}

            # Audit des politiques de catalogue
            print("  📋 Politiques de catalogue:")
            policies = security_manager.get_catalog_item_policies(item_path)

            if policies and policies.get("value"):
                policy_count = len(policies["value"])
                print(f"    📄 {policy_count} politique(s) trouvée(s)")

                for policy in policies["value"][:3]:  # Afficher les 3 premières
                    print(f"    🔐 {policy.get('GroupUserName', 'Unknown')}")

                if policy_count > 3:
                    print(f"    ... et {policy_count - 3} autre(s)")

                audit_results[item_path]["catalog_policies"] = policy_count
            else:
                print("    ⚠️  Aucune politique de catalogue trouvée")
                audit_results[item_path]["catalog_policies"] = 0

        except Exception as e:
            print(f"    💥 Erreur lors de l'audit: {str(e)}")
            audit_results[item_path] = {"error": str(e)}

    # Résumé de l'audit
    print("\n" + "=" * 50)
    print("📈 RÉSUMÉ DE L'AUDIT")
    print("=" * 50)

    total_rls_users = 0
    total_policies = 0

    for item_path, results in audit_results.items():
        if "error" not in results:
            total_rls_users += results.get("rls_users", 0)
            total_policies += results.get("catalog_policies", 0)

            print(f"\n📊 {item_path}:")
            print(f"   👥 Utilisateurs RLS: {results.get('rls_users', 0)}")
            print(f"   📋 Politiques: {results.get('catalog_policies', 0)}")
        else:
            print(f"\n❌ {item_path}: {results['error']}")

    print("\n🎯 TOTAUX:")
    print(f"   👥 Total utilisateurs RLS: {total_rls_users}")
    print(f"   📋 Total politiques: {total_policies}")
    print(f"   📊 Éléments audités: {len(items_to_audit)}")


def example_advanced_security_operations():
    """Exemple d'opérations de sécurité avancées"""

    client = SSRSRestClient(
        server_url=os.getenv("SSRS_SERVER_URL"),
        username=os.getenv("SSRS_USERNAME"),
        password=os.getenv("SSRS_PASSWORD"),
        domain=os.getenv("SSRS_DOMAIN"),
        verify_ssl=False,
    )

    security_manager = SSRSSecurityManager(client)

    print("🚀 Opérations de sécurité avancées")
    print("=" * 50)

    # 1. Synchronisation de sécurité entre environnements
    print("\n1️⃣  Synchronisation entre environnements")

    # Configuration des environnements
    source_reports = {
        "/Test/Test Report": "/Prod/Production Report",
        "/Test/Dashboard": "/Prod/Dashboard",
    }

    for source, target in source_reports.items():
        print(f"\n🔄 Sync {source} → {target}")

        try:
            # Migrer RLS
            rls_success = security_manager.migrate_data_model_role_assignments(
                source, target
            )

            # Migrer politiques
            policy_success = security_manager.migrate_catalog_item_policies(
                source, target
            )

            if rls_success and policy_success:
                print("  ✅ Synchronisation complète réussie")
            elif rls_success:
                print("  ⚠️  RLS synchronisé, échec des politiques")
            elif policy_success:
                print("  ⚠️  Politiques synchronisées, échec RLS")
            else:
                print("  ❌ Échec complet de la synchronisation")

        except Exception as e:
            print(f"  💥 Erreur: {str(e)}")

    # 2. Nettoyage des utilisateurs inactifs
    print("\n2️⃣  Nettoyage des utilisateurs inactifs")

    inactive_users = ["DOMAIN\\old_user1", "DOMAIN\\old_user2"]
    cleanup_reports = ["/PROD/Report", "/PROD/Dashboard"]

    for report in cleanup_reports:
        print(f"\n🧹 Nettoyage de {report}")

        for user in inactive_users:
            try:
                success = security_manager.remove_user_from_role(
                    report_path=report,
                    username=user,
                    role_names=None,  # Retirer de tous les rôles
                )

                if success:
                    print(f"  ✅ Utilisateur {user} retiré")
                else:
                    print(f"  ℹ️  Utilisateur {user} non trouvé")

            except Exception as e:
                print(f"  💥 Erreur pour {user}: {str(e)}")

    # 3. Application de modèles de sécurité standard
    print("\n3️⃣  Application de modèles de sécurité")

    # Modèle de sécurité standard
    security_template = {
        "managers": {
            "users": ["DOMAIN\\manager1", "DOMAIN\\manager2"],
            "roles": ["Manager Role", "Full Access"],
        },
        "analysts": {
            "users": ["DOMAIN\\analyst1", "DOMAIN\\analyst2"],
            "roles": ["Analyst Role", "Read Only"],
        },
        "viewers": {
            "users": ["DOMAIN\\viewer1", "DOMAIN\\viewer2"],
            "roles": ["Viewer Role"],
        },
    }

    target_reports = ["/PROD/NewReport1", "/PROD/NewReport2"]

    for report in target_reports:
        print(f"\n🎯 Application du modèle à {report}")

        for group_name, config in security_template.items():
            print(f"  👥 Groupe: {group_name}")

            for user in config["users"]:
                try:
                    success = security_manager.add_user_to_role(
                        report_path=report, username=user, role_names=config["roles"]
                    )

                    if success:
                        print(
                            f"    ✅ {user} ajouté avec rôles: {', '.join(config['roles'])}"
                        )
                    else:
                        print(f"    ❌ Échec pour {user}")

                except Exception as e:
                    print(f"    💥 Erreur pour {user}: {str(e)}")


if __name__ == "__main__":
    print("🔐 Exemples de gestion de sécurité SSRS PowerBI")
    print("=" * 60)

    try:
        # Exécuter les exemples
        print("\n" + "🔄 RLS Management".center(60, "="))
        example_rls_management()

        print("\n" + "📁 Folder Security Management".center(60, "="))
        example_folder_security_management()

        print("\n" + "📋 Catalog Item Policies".center(60, "="))
        example_catalog_item_policies()

        print("\n" + "👥 Bulk Security Operations".center(60, "="))
        example_bulk_security_operations()

        print("\n" + "🔍 Security Audit".center(60, "="))
        example_security_audit()

        print("\n" + "🚀 Advanced Security Operations".center(60, "="))
        example_advanced_security_operations()

        print("\n🎉 Tous les exemples ont été exécutés avec succès!")

    except Exception as e:
        print(f"\n💥 Erreur lors de l'exécution des exemples: {str(e)}")
        import traceback

        traceback.print_exc()
